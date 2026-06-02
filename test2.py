"""
browser.py — standalone browser activity collector.
Zero local imports — only Python standard library.

Writes every event as a JSON line to:
  LOG_FILE  (default: ~/ueba/t1.json, override with UEBA_LOG env var)

Env vars:
  UEBA_LOG       path to output .jsonl file
  UEBA_STDOUT    set to "1" to also print events to stdout
  STIX_BUNDLE    path to enterprise-attack.json
                 (default: ../enterprise-attack.json relative to this file)
"""

import json, os, platform, re, shutil, sqlite3, sys, tempfile
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

_HERE    = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get(
    "UEBA_LOG",
    os.path.join(os.path.expanduser("~"), "ueba", "t1.json"),  # FIX 1: was hardcoded /home/sadmin/ueba/t1.json
)
_STDOUT  = os.environ.get("UEBA_STDOUT", "0") == "1"

def _write(event: dict):
    event.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
    line = json.dumps(event, ensure_ascii=False) + "\n"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as exc:
        print(f"[browser] write error: {exc}", file=sys.stderr)
    if _STDOUT:
        sys.stdout.write(line)

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK STIX LOOKUP  (self-contained, no mitre_stix module needed)
# ─────────────────────────────────────────────────────────────────────────────

_STIX_PATH  = os.environ.get(
    "STIX_BUNDLE",
    os.path.join(_HERE, "..", "enterprise-attack.json"),
)
_name_to_id: dict = {}
_id_to_obj:  dict = {}

def _load_stix():
    if _name_to_id:
        return
    try:
        with open(_STIX_PATH, encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception:
        return
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x-mitre-deprecated"):
            continue
        eid = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not eid:
            continue
        name = obj.get("name", "")
        _id_to_obj[eid]            = {"id": eid, "name": name}
        _name_to_id[name.lower()]  = eid

def _mid(query: str) -> str:
    """Resolve a technique name/keyword → external_id, or '' if not found."""
    _load_stix()
    if re.match(r"^T\d{4}(\.\d{3})?$", query, re.IGNORECASE):
        return query.upper() if query.upper() in _id_to_obj else ""
    ql = query.lower()
    if ql in _name_to_id:
        return _name_to_id[ql]
    for name, eid in _name_to_id.items():
        if ql in name:
            return eid
    return ""

_MITRE = {
    "browser_visit":       _mid("Browser Information Discovery"),   # T1217
    "browser_account":     _mid("Browser Information Discovery"),   # T1217
    "browser_search":      _mid("Browser Information Discovery"),   # T1217
    "browser_media":       _mid("Browser Information Discovery"),   # T1217
    "browser_download":    _mid("Automated Collection"),            # T1119
    "browser_saved_login": _mid("Credentials from Web Browsers"),   # T1555.003
}

# ─────────────────────────────────────────────────────────────────────────────
# PATH DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

OS = platform.system()

def _chrome_profile_dirs() -> dict:
    if OS == "Linux":
        home = os.path.expanduser("~")
        bases = {
            "chrome": f"{home}/.config/google-chrome",
            "brave":  f"{home}/.config/BraveSoftware/Brave-Browser",
            "edge":   f"{home}/.config/microsoft-edge",
            "opera":  f"{home}/.config/opera",
        }
    else:
        appdata = os.environ.get("LOCALAPPDATA", "")
        roaming  = os.environ.get("APPDATA", "")
        bases = {
            "chrome": rf"{appdata}\Google\Chrome\User Data",
            "brave":  rf"{appdata}\BraveSoftware\Brave-Browser\User Data",
            "edge":   rf"{appdata}\Microsoft\Edge\User Data",
            "opera":  rf"{roaming}\Opera Software\Opera Stable",
        }
    result = {}
    for browser, base in bases.items():
        if not os.path.isdir(base):
            continue
        profile = base if browser == "opera" else os.path.join(base, "Default")
        if os.path.isdir(profile):
            result[browser] = profile
    return result

def _ff_profile_dirs() -> list:
    if OS == "Linux":
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, ".mozilla", "firefox"),                      # native deb/rpm
            os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),  # Ubuntu snap
            os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),  # Flatpak
        ]
    else:
        candidates = [
            os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"),
        ]

    profiles = []
    for ff_dir in candidates:
        if not os.path.isdir(ff_dir):
            continue
        for d in os.listdir(ff_dir):
            p = os.path.join(ff_dir, d)
            if os.path.exists(os.path.join(p, "places.sqlite")):
                profiles.append(p)
    return profiles

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _copy_db(path: str) -> str:
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    shutil.copy2(path, tmp)
    # copy WAL + SHM so we see live data when the browser is open
    for ext in ("-wal", "-shm"):
        src = path + ext
        if os.path.exists(src):
            shutil.copy2(src, tmp + ext)
    return tmp

def _rm_tmp(tmp: str):
    for path in (tmp, tmp + "-wal", tmp + "-shm"):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

def _user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME", "unknown")

_last_visit  = {}
_last_dl     = {}
_last_search = {}
_last_media  = {}
_last_mtime  = {}   # db_path → last seen mtime (skip copy when unchanged)

def _db_changed(db_path: str) -> bool:
    """Return True if db_path (or its WAL) was modified since last check."""
    try:
        mtime = max(
            os.path.getmtime(db_path),
            os.path.getmtime(db_path + "-wal") if os.path.exists(db_path + "-wal") else 0,
        )
    except OSError:
        return False
    if _last_mtime.get(db_path) == mtime:
        return False
    _last_mtime[db_path] = mtime
    return True

_TRANSITION = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
    4: "manual_subframe", 5: "generated", 6: "auto_toplevel",
    7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}
_DL_STATE = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "error", 4: "interrupted"}

# ─────────────────────────────────────────────────────────────────────────────
# 1. ACCOUNT / PROFILE INFO
# ─────────────────────────────────────────────────────────────────────────────

_account_seen: set = set()

def _collect_account(browser: str, profile_dir: str):
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
                "user":         _user(),
                "mitre_id":     _MITRE["browser_account"],
            })
        _account_seen.add(browser)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# 2. SAVED LOGIN USERNAMES
# ─────────────────────────────────────────────────────────────────────────────

_logins_seen: set = set()

def _collect_logins(browser: str, profile_dir: str):
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
                "user":         _user(),
                "mitre_id":     _MITRE["browser_saved_login"],
            })
        conn.close()
        _logins_seen.add(browser)
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 3. BROWSER VISITS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_visits_chrome(browser: str, profile_dir: str):
    db_path = os.path.join(profile_dir, "History")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_visit.get(browser, 0)
        # one row per actual page load (covers every tab separately)
        cur.execute("""
            SELECT v.id,
                   u.url, u.title,
                   datetime(v.visit_time/1000000-11644473600,'unixepoch') AS visit_time,
                   v.transition & 255 AS transition,
                   u.visit_count, u.typed_count
            FROM visits v
            JOIN urls u ON v.url = u.id
            WHERE v.id > ?
            ORDER BY v.id
        """, (last,))
        for vid, url, title, ts, trans, visits, typed in cur.fetchall():
            _last_visit[browser] = max(_last_visit.get(browser, 0), vid)
            _write({
                "event_type":  "browser_visit",
                "browser":     browser,
                "url":         (url or "")[:512],
                "title":       (title or "")[:256],
                "visit_time":  ts,
                "transition":  _TRANSITION.get(trans, str(trans)),
                "visit_count": visits,
                "typed_count": typed,
                "user":        _user(),
                "mitre_id":    _MITRE["browser_visit"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

_FF_VISIT_TYPE = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed",
    5: "redirect_permanent", 6: "redirect_temporary",
    7: "download", 8: "framed_link", 9: "reload",
}

def _collect_visits_firefox(profile_dir: str):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_visit.get("firefox", 0)
        # moz_historyvisits: one row per actual page load, including each tab
        cur.execute("""
            SELECT h.id,
                   p.url, p.title,
                   datetime(h.visit_date/1000000,'unixepoch') AS visit_time,
                   h.visit_type,
                   p.visit_count, p.typed
            FROM moz_historyvisits h
            JOIN moz_places p ON h.place_id = p.id
            WHERE h.id > ?
            ORDER BY h.id
        """, (last,))
        for hid, url, title, ts, vtype, visits, typed in cur.fetchall():
            _last_visit["firefox"] = max(_last_visit.get("firefox", 0), hid)
            _write({
                "event_type":  "browser_visit",
                "browser":     "firefox",
                "url":         (url or "")[:512],
                "title":       (title or "")[:256],
                "visit_time":  ts,
                "transition":  _FF_VISIT_TYPE.get(vtype, str(vtype)),
                "visit_count": visits,
                "typed_count": typed,
                "user":        _user(),
                "mitre_id":    _MITRE["browser_visit"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 4. DOWNLOADS
# ─────────────────────────────────────────────────────────────────────────────

def _collect_downloads_chrome(browser: str, profile_dir: str):
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
                "user":           _user(),
                "mitre_id":       _MITRE["browser_download"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

def _collect_downloads_firefox(profile_dir: str):
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
                   dest.content AS file_uri,
                   meta.content AS meta_json
            FROM moz_places p
            JOIN moz_annos dest ON p.id = dest.place_id
            JOIN moz_anno_attributes da ON dest.anno_attribute_id = da.id
                 AND da.name = 'downloads/destinationFileURI'
            LEFT JOIN moz_annos meta ON p.id = meta.place_id
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
                "user":        _user(),
                "mitre_id":    _MITRE["browser_download"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 5. SEARCH QUERIES
# ─────────────────────────────────────────────────────────────────────────────

def _collect_searches_chrome(browser: str, profile_dir: str):
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
                "user":        _user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

def _collect_searches_firefox(profile_dir: str):
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
                "user":        _user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 6. MEDIA / VIDEO WATCH HISTORY
# ─────────────────────────────────────────────────────────────────────────────

def _collect_media_chrome(browser: str, profile_dir: str):
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
                "user":           _user(),
                "mitre_id":       _MITRE["browser_media"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN COLLECT
# ─────────────────────────────────────────────────────────────────────────────

_DEBUG = False

def _dbg(msg: str):
    if _DEBUG:
        print(f"[debug] {msg}", file=sys.stderr)

def _run(fn, *args, label=""):
    try:
        fn(*args)
    except Exception as e:
        _dbg(f"{label or fn.__name__}: {e}")

def collect():
    chrome = _chrome_profile_dirs()
    ff     = _ff_profile_dirs()
    _dbg(f"chrome profiles: {list(chrome.keys()) or 'none'}")
    _dbg(f"firefox profiles: {len(ff)}")

    for browser, profile_dir in chrome.items():
        # account + logins run once regardless (no mtime needed)
        _run(_collect_account, browser, profile_dir, label=f"{browser}/account")
        _run(_collect_logins,  browser, profile_dir, label=f"{browser}/logins")

        # History DB: check mtime ONCE, then run all three collectors
        history = os.path.join(profile_dir, "History")
        if _db_changed(history):
            _dbg(f"{browser}: History changed, collecting")
            _run(_collect_visits_chrome,    browser, profile_dir, label=f"{browser}/visits")
            _run(_collect_downloads_chrome, browser, profile_dir, label=f"{browser}/downloads")
            _run(_collect_searches_chrome,  browser, profile_dir, label=f"{browser}/searches")
        else:
            _dbg(f"{browser}: History unchanged, skipping")

        # Media History: separate DB, separate check
        media = os.path.join(profile_dir, "Media History")
        if _db_changed(media):
            _run(_collect_media_chrome, browser, profile_dir, label=f"{browser}/media")

    for profile_dir in ff:
        _dbg(f"firefox profile: {profile_dir}")
        # places.sqlite: check mtime ONCE, then run all three collectors
        places = os.path.join(profile_dir, "places.sqlite")
        if _db_changed(places):
            _dbg("firefox: places.sqlite changed, collecting")
            _run(_collect_visits_firefox,    profile_dir, label="firefox/visits")
            _run(_collect_downloads_firefox, profile_dir, label="firefox/downloads")
            _run(_collect_searches_firefox,  profile_dir, label="firefox/searches")
        else:
            _dbg("firefox: places.sqlite unchanged, skipping")


if __name__ == "__main__":
    import time, argparse

    ap = argparse.ArgumentParser(description="Standalone browser activity collector")
    ap.add_argument("--interval", type=int, default=5,
                    help="polling interval in seconds (default: 5)")
    ap.add_argument("--once", action="store_true",
                    help="run once and exit")
    ap.add_argument("--debug", action="store_true",
                    help="print diagnostic info to stderr")
    ap.add_argument("--stix", metavar="PATH",
                    help="path to enterprise-attack.json (overrides STIX_BUNDLE env var)")
    args = ap.parse_args()

    if args.debug:
        _DEBUG = True
    if args.stix:
        _STIX_PATH = args.stix
        _name_to_id.clear()
        _id_to_obj.clear()
        _MITRE["browser_visit"]       = _mid("Browser Information Discovery")
        _MITRE["browser_account"]     = _mid("Browser Information Discovery")
        _MITRE["browser_search"]      = _mid("Browser Information Discovery")
        _MITRE["browser_media"]       = _mid("Browser Information Discovery")
        _MITRE["browser_download"]    = _mid("Automated Collection")
        _MITRE["browser_saved_login"] = _mid("Credentials from Web Browsers")

    print(f"[browser] output  -> {LOG_FILE}")
    print(f"[browser] STIX    -> {_STIX_PATH}  ({'found' if os.path.exists(_STIX_PATH) else 'NOT FOUND - MITRE IDs will be empty'})")
    print(f"[browser] MITRE   -> { {k: v for k, v in _MITRE.items() if v} or 'none resolved' }")

    chrome = _chrome_profile_dirs()
    ff     = _ff_profile_dirs()
    print(f"[browser] chrome  -> {list(chrome.keys()) or 'none found'}")
    print(f"[browser] firefox -> {len(ff)} profile(s)")
    for p in ff:
        print(f"           {p}")

    if not chrome and not ff:
        print("[browser] WARNING: no browser profiles found — nothing to collect")

    if args.once:
        collect()
        print(f"[browser] done — check {LOG_FILE}")
    else:
        print(f"[browser] polling every {args.interval}s  (Ctrl+C to stop)")
        while True:
            collect()
            time.sleep(args.interval)
