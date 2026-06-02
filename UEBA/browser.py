import os, platform, sqlite3, shutil, tempfile, json
from writer import write
from mitre_stix import resolve_id as _mid

# ── Test log file ─────────────────────────────────────────────────────────────
# Every event is appended here as a JSON line for local inspection / testing.
LOG_FILE = os.path.join(os.path.dirname(__file__), "browser_test.jsonl")

def _write(event: dict):
    write("browser", event)
    with open(LOG_FILE, "a", encoding="utf-8") as _f:
        _f.write(json.dumps(event) + "\n")

OS  = platform.system()

# Resolve MITRE technique IDs once at import time from the local STIX bundle.
# If the bundle is unavailable the strings fall back to empty (no crash).
_MITRE = {
    # ── Discovery ────────────────────────────────────────────────────────────
    "browser_visit":        _mid("Browser Information Discovery"),   # T1217
    "browser_account":      _mid("Browser Information Discovery"),   # T1217
    "browser_search":       _mid("Browser Information Discovery"),   # T1217
    "browser_media":        _mid("Browser Information Discovery"),   # T1217
    # ── Collection ───────────────────────────────────────────────────────────
    "browser_download":     _mid("Automated Collection"),            # T1119
    # ── Credential Access ────────────────────────────────────────────────────
    "browser_saved_login":  _mid("Credentials from Web Browsers"),   # T1555.003
}

# ─────────────────────────────────────────────────────────────────────────────
# PATH DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def _chrome_profile_dirs():
    """Return {browser: profile_dir} for installed Chromium-based browsers."""
    if OS == "Linux":
        home = os.path.expanduser("~")
        bases = {
            "chrome": f"{home}/.config/google-chrome",
            "brave":  f"{home}/.config/BraveSoftware/Brave-Browser",
            "edge":   f"{home}/.config/microsoft-edge",
            "opera":  f"{home}/.config/opera",
        }
        opera_direct = True
    else:
        appdata = os.environ.get("LOCALAPPDATA", "")
        roaming  = os.environ.get("APPDATA", "")
        bases = {
            "chrome": rf"{appdata}\Google\Chrome\User Data",
            "brave":  rf"{appdata}\BraveSoftware\Brave-Browser\User Data",
            "edge":   rf"{appdata}\Microsoft\Edge\User Data",
            "opera":  rf"{roaming}\Opera Software\Opera Stable",
        }
        opera_direct = True   # Opera keeps files in base dir, not a "Default" sub-dir

    result = {}
    for browser, base in bases.items():
        if not os.path.isdir(base):
            continue
        profile = base if (browser == "opera" and opera_direct) else os.path.join(base, "Default")
        if os.path.isdir(profile):
            result[browser] = profile
    return result

def _ff_profile_dirs():
    """Return list of Firefox profile directories that contain places.sqlite."""
    if OS == "Linux":
        home = os.path.expanduser("~")
        ff_dir = f"{home}/.mozilla/firefox"
    else:
        ff_dir = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(ff_dir):
        return []
    return [
        os.path.join(ff_dir, d) for d in os.listdir(ff_dir)
        if os.path.exists(os.path.join(ff_dir, d, "places.sqlite"))
    ]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _copy_db(path):
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    shutil.copy2(path, tmp)
    return tmp

def _current_user():
    return os.environ.get("USER") or os.environ.get("USERNAME", "unknown")

# last-seen id trackers so repeated calls only emit new rows
_last_visit  = {}
_last_dl     = {}
_last_search = {}
_last_media  = {}

_TRANSITION = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
    4: "manual_subframe", 5: "generated", 6: "auto_toplevel",
    7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}

_DL_STATE = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "error", 4: "interrupted"}

# ─────────────────────────────────────────────────────────────────────────────
# 1. ACCOUNT / PROFILE INFO  (Chromium Preferences JSON — emitted once)
# ─────────────────────────────────────────────────────────────────────────────
_account_seen = set()

def _collect_account(browser, profile_dir):
    if browser in _account_seen:
        return
    prefs_path = os.path.join(profile_dir, "Preferences")
    if not os.path.exists(prefs_path):
        return
    try:
        with open(prefs_path, encoding="utf-8") as f:
            prefs = json.load(f)
        accounts = prefs.get("account_info", [])
        if not accounts:
            email = prefs.get("signin", {}).get("allowed", "")
            if email:
                accounts = [{"email": email}]
        for acc in accounts:
            _write({
                "event_type":   "browser_account",
                "browser":      browser,
                "email":        acc.get("email", ""),
                "full_name":    acc.get("full_name", ""),
                "given_name":   acc.get("given_name", ""),
                "account_id":   acc.get("gaia", ""),
                "locale":       acc.get("locale", ""),
                "profile_name": prefs.get("profile", {}).get("name", ""),
                "user":         _current_user(),
                "mitre_id":     _MITRE["browser_account"],
            })
        _account_seen.add(browser)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# 2. SAVED LOGIN USERNAMES  (Login Data DB — usernames only, no passwords)
# ─────────────────────────────────────────────────────────────────────────────
_logins_seen = set()

def _collect_logins(browser, profile_dir):
    if browser in _logins_seen:
        return
    db_path = os.path.join(profile_dir, "Login Data")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        cur.execute("""
            SELECT origin_url, username_value,
                   datetime(date_created/1000000-11644473600,'unixepoch'),
                   times_used
            FROM logins
            WHERE username_value != ''
            ORDER BY date_created
        """)
        for origin, username, created, uses in cur.fetchall():
            _write({
                "event_type":   "browser_saved_login",
                "browser":      browser,
                "origin_url":   (origin or "")[:512],
                "username":     (username or "")[:256],
                "date_created": created,
                "times_used":   uses,
                "user":         _current_user(),
                "mitre_id":     _MITRE["browser_saved_login"],
            })
        conn.close()
        _logins_seen.add(browser)
    finally:
        os.unlink(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 3. BROWSER VISITS  (enhanced with typed_count + transition type)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_visits_chrome(browser, profile_dir):
    db_path = os.path.join(profile_dir, "History")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_visit.get(browser, 0)
        cur.execute("""
            SELECT u.id, u.url, u.title, u.visit_count, u.typed_count,
                   datetime(u.last_visit_time/1000000-11644473600,'unixepoch'),
                   (SELECT transition & 255 FROM visits
                    WHERE url = u.id ORDER BY visit_time DESC LIMIT 1)
            FROM urls u
            WHERE u.id > ?
            ORDER BY u.id
        """, (last,))
        for uid, url, title, visits, typed, ts, trans in cur.fetchall():
            _last_visit[browser] = max(_last_visit.get(browser, 0), uid)
            _write({
                "event_type":   "browser_visit",
                "browser":      browser,
                "url":          (url or "")[:512],
                "title":        (title or "")[:256],
                "visit_count":  visits,
                "typed_count":  typed,
                "transition":   _TRANSITION.get(trans, str(trans)),
                "last_visit":   ts,
                "user":         _current_user(),
                "mitre_id":     _MITRE["browser_visit"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

def _collect_visits_firefox(profile_dir):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_visit.get("firefox", 0)
        cur.execute("""
            SELECT id, url, title, visit_count, typed,
                   datetime(last_visit_date/1000000,'unixepoch')
            FROM moz_places
            WHERE id > ?
            ORDER BY id
        """, (last,))
        for uid, url, title, visits, typed, ts in cur.fetchall():
            _last_visit["firefox"] = max(_last_visit.get("firefox", 0), uid)
            _write({
                "event_type":   "browser_visit",
                "browser":      "firefox",
                "url":          (url or "")[:512],
                "title":        (title or "")[:256],
                "visit_count":  visits,
                "typed_count":  typed,
                "last_visit":   ts,
                "user":         _current_user(),
                "mitre_id":     _MITRE["browser_visit"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 4. DOWNLOADS  (file name, path, MIME, size, state)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_downloads_chrome(browser, profile_dir):
    db_path = os.path.join(profile_dir, "History")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_dl.get(browser, 0)
        cur.execute("""
            SELECT d.id, d.current_path, d.target_path,
                   datetime(d.start_time/1000000-11644473600,'unixepoch'),
                   datetime(d.end_time/1000000-11644473600,'unixepoch'),
                   d.received_bytes, d.total_bytes, d.state,
                   d.mime_type, d.original_mime_type,
                   u.url
            FROM downloads d
            LEFT JOIN downloads_url_chains u ON d.id = u.id AND u.chain_index = 0
            WHERE d.id > ?
            ORDER BY d.id
        """, (last,))
        for row in cur.fetchall():
            (did, cur_path, tgt_path,
             start, end, recv, total, state,
             mime, orig_mime, url) = row
            _last_dl[browser] = max(_last_dl.get(browser, 0), did)
            fpath = tgt_path or cur_path or ""
            _write({
                "event_type":     "browser_download",
                "browser":        browser,
                "url":            (url or "")[:512],
                "file_path":      fpath[:512],
                "file_name":      os.path.basename(fpath),
                "mime_type":      mime or orig_mime or "",
                "size_bytes":     total,
                "received_bytes": recv,
                "state":          _DL_STATE.get(state, str(state)),
                "start_time":     start,
                "end_time":       end,
                "user":           _current_user(),
                "mitre_id":       _MITRE["browser_download"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

def _collect_downloads_firefox(profile_dir):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_dl.get("firefox", 0)
        cur.execute("""
            SELECT p.id, p.url,
                   datetime(p.last_visit_date/1000000,'unixepoch'),
                   dest.content   AS file_uri,
                   meta.content   AS meta_json
            FROM moz_places p
            JOIN moz_annos dest ON p.id = dest.place_id
            JOIN moz_anno_attributes da  ON dest.anno_attribute_id = da.id
                 AND da.name = 'downloads/destinationFileURI'
            LEFT JOIN moz_annos meta      ON p.id = meta.place_id
            LEFT JOIN moz_anno_attributes ma ON meta.anno_attribute_id = ma.id
                 AND ma.name = 'downloads/metaData'
            WHERE p.id > ?
            ORDER BY p.id
        """, (last,))
        for pid, url, ts, file_uri, meta_json in cur.fetchall():
            _last_dl["firefox"] = max(_last_dl.get("firefox", 0), pid)
            meta = {}
            try:
                meta = json.loads(meta_json or "{}")
            except Exception:
                pass
            fpath = (file_uri or "").replace("file:///", "").replace("%20", " ")
            _write({
                "event_type":  "browser_download",
                "browser":     "firefox",
                "url":         (url or "")[:512],
                "file_path":   fpath[:512],
                "file_name":   os.path.basename(fpath),
                "mime_type":   meta.get("type", ""),
                "size_bytes":  meta.get("fileSize", 0),
                "state":       meta.get("state", ""),
                "end_time":    ts,
                "user":        _current_user(),
                "mitre_id":    _MITRE["browser_download"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 5. SEARCH QUERIES
# ─────────────────────────────────────────────────────────────────────────────

def _collect_searches_chrome(browser, profile_dir):
    db_path = os.path.join(profile_dir, "History")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_search.get(browser, 0)
        cur.execute("""
            SELECT u.id, ks.term, u.url, u.title,
                   datetime(u.last_visit_time/1000000-11644473600,'unixepoch')
            FROM keyword_search_terms ks
            JOIN urls u ON ks.url_id = u.id
            WHERE u.id > ?
            ORDER BY u.id
        """, (last,))
        for uid, term, url, title, ts in cur.fetchall():
            _last_search[browser] = max(_last_search.get(browser, 0), uid)
            _write({
                "event_type":  "browser_search",
                "browser":     browser,
                "search_term": (term or "")[:512],
                "url":         (url or "")[:512],
                "title":       (title or "")[:256],
                "timestamp":   ts,
                "user":        _current_user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

def _collect_searches_firefox(profile_dir):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_search.get("firefox", 0)
        cur.execute("""
            SELECT ROWID, input, use_count
            FROM moz_inputhistory
            WHERE ROWID > ?
            ORDER BY ROWID
        """, (last,))
        for rowid, term, count in cur.fetchall():
            _last_search["firefox"] = max(_last_search.get("firefox", 0), rowid)
            _write({
                "event_type":  "browser_search",
                "browser":     "firefox",
                "search_term": (term or "")[:512],
                "use_count":   count,
                "user":        _current_user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 6. MEDIA / VIDEO WATCH HISTORY  (Chromium "Media History" DB)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_media_chrome(browser, profile_dir):
    db_path = os.path.join(profile_dir, "Media History")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_media.get(browser, 0)
        cur.execute("""
            SELECT ps.id, u.url,
                   ps.title, ps.artist, ps.album, ps.source_title,
                   ps.duration_ms, ps.position_ms,
                   ps.last_updated_time_s,
                   p.has_video, p.has_audio, p.watch_time_s
            FROM playbackSession ps
            JOIN urls u ON ps.url_id = u.id
            LEFT JOIN playback p ON ps.url_id = p.url_id
            WHERE ps.id > ?
            ORDER BY ps.id
        """, (last,))
        for row in cur.fetchall():
            (sid, url, title, artist, album, source,
             dur_ms, pos_ms, updated,
             has_video, has_audio, watch_s) = row
            _last_media[browser] = max(_last_media.get(browser, 0), sid)
            _write({
                "event_type":     "browser_media",
                "browser":        browser,
                "url":            (url or "")[:512],
                "media_title":    (title or "")[:256],
                "artist":         (artist or "")[:256],
                "album":          (album or "")[:256],
                "source":         (source or "")[:256],
                "duration_sec":   round(dur_ms / 1000, 1) if dur_ms else None,
                "position_sec":   round(pos_ms / 1000, 1) if pos_ms else None,
                "watch_time_sec": round(watch_s, 1) if watch_s else None,
                "has_video":      bool(has_video),
                "has_audio":      bool(has_audio),
                "last_updated":   updated,
                "user":           _current_user(),
                "mitre_id":       _MITRE["browser_media"],
            })
        conn.close()
    finally:
        os.unlink(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN COLLECT
# ─────────────────────────────────────────────────────────────────────────────

def collect():
    for browser, profile_dir in _chrome_profile_dirs().items():
        for fn in (_collect_account, _collect_logins,
                   _collect_visits_chrome, _collect_downloads_chrome,
                   _collect_searches_chrome, _collect_media_chrome):
            try:
                fn(browser, profile_dir)
            except Exception:
                pass

    for profile_dir in _ff_profile_dirs():
        for fn in (_collect_visits_firefox, _collect_downloads_firefox,
                   _collect_searches_firefox):
            try:
                fn(profile_dir)
            except Exception:
                pass
