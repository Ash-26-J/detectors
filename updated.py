"""
browser.py — standalone browser activity collector.
Zero local imports — only Python standard library.

Writes every event as a JSON line to:
  LOG_FILE  (default: auto-detected per OS, override with UEBA_LOG env var)

Env vars:
  UEBA_LOG       path to output .jsonl file
  UEBA_STDOUT    set to "1" to also print events to stdout
  STIX_BUNDLE    path to enterprise-attack.json
                 (default: ../enterprise-attack.json relative to this file)
"""

import json, os, platform, re, shutil, socket, sqlite3, sys, tempfile
import urllib.request, urllib.parse, urllib.error, html, html.parser
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))
OS    = platform.system()

def _default_log_path() -> str:
    if OS == "Windows":
        base = os.environ.get("USERPROFILE", "C:\\Users\\vladmin")
        return os.path.join(base, "Documents", "testing", "t1.json")
    else:
        return "/home/sadmin/ueba/t1.json"

LOG_FILE = os.environ.get("UEBA_LOG", _default_log_path())
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
# MITRE ATT&CK STIX LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

_STIX_PATH = os.environ.get(
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
        _id_to_obj[eid]           = {"id": eid, "name": name}
        _name_to_id[name.lower()] = eid

def _mid(query: str) -> str:
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
    "browser_visit":       _mid("Browser Information Discovery"),
    "browser_account":     _mid("Browser Information Discovery"),
    "browser_search":      _mid("Browser Information Discovery"),
    "browser_media":       _mid("Browser Information Discovery"),
    "browser_download":    _mid("Automated Collection"),
    "browser_saved_login": _mid("Credentials from Web Browsers"),
    "browser_dns":         _mid("Browser Information Discovery"),
    "browser_content":     _mid("Automated Collection"),
}

# ─────────────────────────────────────────────────────────────────────────────
# PATH DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def _real_home() -> str:
    """
    Return the real user home even when running as root/sudo on Linux.
    On Windows just returns the normal home.
    """
    home = os.path.expanduser("~")
    if OS == "Windows":
        return home
    if home != "/root":
        return home
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user:
        candidate = os.path.join("/home", sudo_user)
        if os.path.isdir(candidate):
            return candidate
    if os.path.isdir("/home/sadmin"):
        return "/home/sadmin"
    return home


def _chrome_profile_dirs() -> dict:
    home = _real_home()
    if OS == "Linux":
        bases = {
            "chrome":        f"{home}/.config/google-chrome",
            "chromium":      f"{home}/.config/chromium",
            "brave":         f"{home}/.config/BraveSoftware/Brave-Browser",
            "edge":          f"{home}/.config/microsoft-edge",
            "opera":         f"{home}/.config/opera",
            "vivaldi":       f"{home}/.config/vivaldi",
            "duckduckgo":    f"{home}/.config/DuckDuckGo/Browser",
            "yandex":        f"{home}/.config/yandex-browser",
            "chrome_snap":   f"{home}/snap/google-chrome/current/.config/google-chrome",
            "chromium_snap": f"{home}/snap/chromium/current/.config/chromium",
            "brave_snap":    f"{home}/snap/brave/current/.config/BraveSoftware/Brave-Browser",
            "edge_snap":     f"{home}/snap/microsoft-edge/current/.config/microsoft-edge",
        }
    elif OS == "Darwin":
        lib = f"{home}/Library/Application Support"
        bases = {
            "chrome":     f"{lib}/Google/Chrome",
            "chromium":   f"{lib}/Chromium",
            "brave":      f"{lib}/BraveSoftware/Brave-Browser",
            "edge":       f"{lib}/Microsoft Edge",
            "opera":      f"{lib}/com.operasoftware.Opera",
            "vivaldi":    f"{lib}/Vivaldi",
            "duckduckgo": f"{lib}/DuckDuckGo/Browser",
            "arc":        f"{lib}/Arc/User Data",
            "yandex":     f"{lib}/Yandex/YandexBrowser",
        }
    else:  # Windows
        appdata = os.environ.get("LOCALAPPDATA", "")
        roaming = os.environ.get("APPDATA", "")
        bases = {
            "chrome":     os.path.join(appdata, "Google", "Chrome", "User Data"),
            "chromium":   os.path.join(appdata, "Chromium", "User Data"),
            "brave":      os.path.join(appdata, "BraveSoftware", "Brave-Browser", "User Data"),
            "edge":       os.path.join(appdata, "Microsoft", "Edge", "User Data"),
            "opera":      os.path.join(roaming, "Opera Software", "Opera Stable"),
            "vivaldi":    os.path.join(appdata, "Vivaldi", "User Data"),
            "duckduckgo": os.path.join(appdata, "DuckDuckGo", "Browser", "User Data"),
            "arc":        os.path.join(appdata, "Arc", "User Data"),
            "yandex":     os.path.join(appdata, "Yandex", "YandexBrowser", "User Data"),
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
    home = _real_home()
    if OS == "Linux":
        candidates = [
            ("firefox",   os.path.join(home, ".mozilla", "firefox")),
            ("librewolf", os.path.join(home, ".librewolf")),
            ("waterfox",  os.path.join(home, ".waterfox")),
            ("floorp",    os.path.join(home, ".floorp")),
            ("firefox",   os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox")),
            ("firefox",   os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox")),
            ("librewolf", os.path.join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf")),
            ("waterfox",  os.path.join(home, ".var", "app", "net.waterfox.waterfox", ".waterfox")),
        ]
    elif OS == "Darwin":
        lib = f"{home}/Library/Application Support"
        candidates = [
            ("firefox",   os.path.join(lib, "Firefox", "Profiles")),
            ("librewolf", os.path.join(lib, "LibreWolf", "Profiles")),
            ("waterfox",  os.path.join(lib, "Waterfox", "Profiles")),
            ("floorp",    os.path.join(lib, "Floorp", "Profiles")),
        ]
    else:  # Windows
        appdata = os.environ.get("APPDATA", "")
        candidates = [
            ("firefox",   os.path.join(appdata, "Mozilla",   "Firefox",   "Profiles")),
            ("librewolf", os.path.join(appdata, "LibreWolf", "LibreWolf", "Profiles")),
            ("waterfox",  os.path.join(appdata, "Waterfox",  "Waterfox",  "Profiles")),
            ("floorp",    os.path.join(appdata, "Floorp",    "Floorp",    "Profiles")),
        ]

    profiles = []
    seen = set()
    for browser_name, root in candidates:
        if not os.path.isdir(root):
            continue
        for d in os.listdir(root):
            p = os.path.join(root, d)
            real = os.path.realpath(p)
            if real in seen:
                continue
            if os.path.exists(os.path.join(p, "places.sqlite")):
                seen.add(real)
                profiles.append((browser_name, p))
    return profiles

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _copy_db(path: str) -> str:
    fd, tmp = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    shutil.copy2(path, tmp)
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
    return (os.environ.get("SUDO_USER")
            or os.environ.get("USER")
            or os.environ.get("USERNAME", "unknown"))

_last_visit  = {}
_last_dl     = {}
_last_search = {}
_last_media  = {}
_last_mtime  = {}

def _db_changed(db_path: str) -> bool:
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
# DNS LOOKUP + IP ENRICHMENT
# ─────────────────────────────────────────────────────────────────────────────

_dns_cache: dict = {}

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

def _get_dns_server() -> str:
    if OS != "Windows":
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except Exception:
            pass
    else:
        try:
            import subprocess
            out = subprocess.check_output(
                ["ipconfig", "/all"], encoding="utf-8", errors="ignore"
            )
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return parts[-1].strip()
        except Exception:
            pass
    return ""

_LOCAL_IP   = _get_local_ip()
_DNS_SERVER = _get_dns_server()

def _resolve_domain(domain: str) -> str:
    if domain in _dns_cache:
        return _dns_cache[domain]
    try:
        ip = socket.gethostbyname(domain)
        _dns_cache[domain] = ip
        return ip
    except Exception:
        _dns_cache[domain] = ""
        return ""

def _enrich_url(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        domain = ""
    dest_ip = _resolve_domain(domain) if domain else ""
    return {
        "src_ip":     _LOCAL_IP,
        "dest_ip":    dest_ip,
        "dns_server": _DNS_SERVER,
        "domain":     domain,
    }

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONTENT FETCH
# ─────────────────────────────────────────────────────────────────────────────

_content_cache: dict = {}
_CONTENT_MAX_CHARS = int(os.environ.get("UEBA_CONTENT_MAX", "2000"))

_SKIP_CONTENT_DOMAINS = {
    "google.com", "www.google.com",
    "bing.com", "www.bing.com",
    "duckduckgo.com", "www.duckduckgo.com",
    "yahoo.com", "search.yahoo.com",
    "accounts.google.com",
    "localhost", "127.0.0.1",
}

class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts    = []
        self._skip     = False
        self._skip_tags = {"script", "style", "noscript", "head"}

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._skip_tags:
            self._skip = True

    def handle_endtag(self, tag):
        if tag.lower() in self._skip_tags:
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            stripped = data.strip()
            if stripped:
                self._parts.append(stripped)

    def get_text(self) -> str:
        return " ".join(self._parts)


def _fetch_page_content(url: str) -> str:
    if url in _content_cache:
        return _content_cache[url]
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            _content_cache[url] = ""
            return ""
        domain = (parsed.hostname or "").lower()
        bare = domain[4:] if domain.startswith("www.") else domain
        if domain in _SKIP_CONTENT_DOMAINS or bare in _SKIP_CONTENT_DOMAINS:
            _content_cache[url] = ""
            return ""
    except Exception:
        _content_cache[url] = ""
        return ""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "text/plain" not in content_type:
                _content_cache[url] = ""
                return ""
            raw = resp.read(1024 * 256)
            charset = "utf-8"
            ct_lower = content_type.lower()
            if "charset=" in ct_lower:
                charset = ct_lower.split("charset=")[-1].split(";")[0].strip()
            body = raw.decode(charset, errors="replace")
    except Exception:
        _content_cache[url] = ""
        return ""
    try:
        parser = _TextExtractor()
        parser.feed(body)
        text = re.sub(r"\s+", " ", parser.get_text()).strip()
        text = text[:_CONTENT_MAX_CHARS]
    except Exception:
        text = ""
    _content_cache[url] = text
    return text


def _extract_search_query(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param in ("q", "query", "text", "p", "wd", "search_query"):
            if param in qs:
                return qs[param][0]
    except Exception:
        pass
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. ACCOUNT / PROFILE INFO  (Chromium-based only)
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
# 2. SAVED LOGIN USERNAMES  (Chromium-based only)
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
# 3. BROWSER VISITS  (+DNS enrichment +page content)
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
            net     = _enrich_url(url)
            sq      = _extract_search_query(url)
            content = _fetch_page_content(url) if not sq else ""
            _write({
                "event_type":   "browser_visit",
                "browser":      browser,
                "url":          (url or "")[:512],
                "title":        (title or "")[:256],
                "visit_time":   ts,
                "transition":   _TRANSITION.get(trans, str(trans)),
                "visit_count":  visits,
                "typed_count":  typed,
                "domain":       net["domain"],
                "src_ip":       net["src_ip"],
                "dest_ip":      net["dest_ip"],
                "dns_server":   net["dns_server"],
                "search_query": sq,
                "page_content": content,
                "user":         _user(),
                "mitre_id":     _MITRE["browser_visit"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

_FF_VISIT_TYPE = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed",
    5: "redirect_permanent", 6: "redirect_temporary",
    7: "download", 8: "framed_link", 9: "reload",
}

def _collect_visits_firefox(browser: str, profile_dir: str):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    key = f"{browser}:{profile_dir}"
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_visit.get(key, 0)
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
            _last_visit[key] = max(_last_visit.get(key, 0), hid)
            net     = _enrich_url(url)
            sq      = _extract_search_query(url)
            content = _fetch_page_content(url) if not sq else ""
            _write({
                "event_type":   "browser_visit",
                "browser":      browser,
                "url":          (url or "")[:512],
                "title":        (title or "")[:256],
                "visit_time":   ts,
                "transition":   _FF_VISIT_TYPE.get(vtype, str(vtype)),
                "visit_count":  visits,
                "typed_count":  typed,
                "domain":       net["domain"],
                "src_ip":       net["src_ip"],
                "dest_ip":      net["dest_ip"],
                "dns_server":   net["dns_server"],
                "search_query": sq,
                "page_content": content,
                "user":         _user(),
                "mitre_id":     _MITRE["browser_visit"],
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
            net   = _enrich_url(url or "")
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
                "domain":         net["domain"],
                "src_ip":         net["src_ip"],
                "dest_ip":        net["dest_ip"],
                "dns_server":     net["dns_server"],
                "user":           _user(),
                "mitre_id":       _MITRE["browser_download"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

def _collect_downloads_firefox(browser: str, profile_dir: str):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    key = f"{browser}:{profile_dir}"
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_dl.get(key, 0)
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
            _last_dl[key] = max(_last_dl.get(key, 0), pid)
            meta = {}
            try:
                meta = json.loads(meta_json or "{}")
            except Exception:
                pass
            fpath = (file_uri or "").replace("file:///", "").replace("%20", " ")
            net   = _enrich_url(url or "")
            _write({
                "event_type":  "browser_download",
                "browser":     browser,
                "url":         (url or "")[:512],
                "file_path":   fpath[:512],
                "file_name":   os.path.basename(fpath),
                "mime_type":   meta.get("type", ""),
                "size_bytes":  meta.get("fileSize", 0),
                "state":       meta.get("state", ""),
                "end_time":    ts,
                "domain":      net["domain"],
                "src_ip":      net["src_ip"],
                "dest_ip":     net["dest_ip"],
                "dns_server":  net["dns_server"],
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
            net = _enrich_url(url)
            _write({
                "event_type":  "browser_search",
                "browser":     browser,
                "search_term": (term or "")[:512],
                "url":         (url or "")[:512],
                "title":       (title or "")[:256],
                "timestamp":   ts,
                "domain":      net["domain"],
                "src_ip":      net["src_ip"],
                "dest_ip":     net["dest_ip"],
                "dns_server":  net["dns_server"],
                "user":        _user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

def _collect_searches_firefox(browser: str, profile_dir: str):
    db_path = os.path.join(profile_dir, "places.sqlite")
    if not os.path.exists(db_path):
        return
    tmp = _copy_db(db_path)
    key = f"{browser}:{profile_dir}"
    try:
        conn = sqlite3.connect(tmp)
        cur  = conn.cursor()
        last = _last_search.get(key, 0)
        cur.execute("""
            SELECT ROWID, input, use_count
            FROM moz_inputhistory
            WHERE ROWID > ?
            ORDER BY ROWID
        """, (last,))
        for rowid, term, count in cur.fetchall():
            _last_search[key] = max(_last_search.get(key, 0), rowid)
            _write({
                "event_type":  "browser_search",
                "browser":     browser,
                "search_term": (term or "")[:512],
                "use_count":   count,
                "user":        _user(),
                "mitre_id":    _MITRE["browser_search"],
            })
        conn.close()
    finally:
        _rm_tmp(tmp)

# ─────────────────────────────────────────────────────────────────────────────
# 6. MEDIA / VIDEO WATCH HISTORY  (Chromium-based only)
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
            net = _enrich_url(url)
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
                "domain":         net["domain"],
                "src_ip":         net["src_ip"],
                "dest_ip":        net["dest_ip"],
                "dns_server":     net["dns_server"],
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
    chrome_profiles = _chrome_profile_dirs()
    ff_profiles     = _ff_profile_dirs()
    _dbg(f"chromium profiles: {list(chrome_profiles.keys()) or 'none'}")
    _dbg(f"firefox-based profiles: {len(ff_profiles)}")

    for browser, profile_dir in chrome_profiles.items():
        _run(_collect_account, browser, profile_dir, label=f"{browser}/account")
        _run(_collect_logins,  browser, profile_dir, label=f"{browser}/logins")

        history = os.path.join(profile_dir, "History")
        if _db_changed(history):
            _dbg(f"{browser}: History changed, collecting")
            _run(_collect_visits_chrome,    browser, profile_dir, label=f"{browser}/visits")
            _run(_collect_downloads_chrome, browser, profile_dir, label=f"{browser}/downloads")
            _run(_collect_searches_chrome,  browser, profile_dir, label=f"{browser}/searches")
        else:
            _dbg(f"{browser}: History unchanged, skipping")

        media = os.path.join(profile_dir, "Media History")
        if _db_changed(media):
            _run(_collect_media_chrome, browser, profile_dir, label=f"{browser}/media")

    for browser, profile_dir in ff_profiles:
        _dbg(f"{browser} profile: {profile_dir}")
        places = os.path.join(profile_dir, "places.sqlite")
        if _db_changed(places):
            _dbg(f"{browser}: places.sqlite changed, collecting")
            _run(_collect_visits_firefox,    browser, profile_dir, label=f"{browser}/visits")
            _run(_collect_downloads_firefox, browser, profile_dir, label=f"{browser}/downloads")
            _run(_collect_searches_firefox,  browser, profile_dir, label=f"{browser}/searches")
        else:
            _dbg(f"{browser}: places.sqlite unchanged, skipping")


if __name__ == "__main__":
    import time, argparse

    ap = argparse.ArgumentParser(description="Standalone browser activity collector")
    ap.add_argument("--interval", type=int, default=5,
                    help="polling interval in seconds (default: 5)")
    ap.add_argument("--once", action="store_true",
                    help="run once and exit")
    ap.add_argument("--debug", action="store_true",
                    help="print diagnostic info to stderr")
    ap.add_argument("--no-content", action="store_true",
                    help="disable page content fetching (faster)")
    ap.add_argument("--stix", metavar="PATH",
                    help="path to enterprise-attack.json (overrides STIX_BUNDLE env var)")
    args = ap.parse_args()

    if args.debug:
        _DEBUG = True
    if args.no_content:
        def _fetch_page_content(url: str) -> str:
            return ""
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
        _MITRE["browser_dns"]         = _mid("Browser Information Discovery")
        _MITRE["browser_content"]     = _mid("Automated Collection")

    print(f"[browser] output     -> {LOG_FILE}")
    print(f"[browser] STIX       -> {_STIX_PATH}  ({'found' if os.path.exists(_STIX_PATH) else 'NOT FOUND - MITRE IDs will be empty'})")
    print(f"[browser] MITRE      -> { {k: v for k, v in _MITRE.items() if v} or 'none resolved' }")
    print(f"[browser] home       -> {_real_home()}")
    print(f"[browser] src_ip     -> {_LOCAL_IP}")
    print(f"[browser] dns_server -> {_DNS_SERVER}")
    print(f"[browser] content    -> {'disabled' if args.no_content else f'enabled (max {_CONTENT_MAX_CHARS} chars)'}")

    chrome_profiles = _chrome_profile_dirs()
    ff_profiles     = _ff_profile_dirs()
    print(f"[browser] chromium-based -> {list(chrome_profiles.keys()) or 'none found'}")
    print(f"[browser] firefox-based  -> {len(ff_profiles)} profile(s)")
    for name, p in ff_profiles:
        print(f"           [{name}] {p}")

    if not chrome_profiles and not ff_profiles:
        print("[browser] WARNING: no browser profiles found — nothing to collect")

    if args.once:
        collect()
        print(f"[browser] done — check {LOG_FILE}")
    else:
        print(f"[browser] polling every {args.interval}s  (Ctrl+C to stop)")
        while True:
            collect()
            time.sleep(args.interval)
