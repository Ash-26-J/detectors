"""
sysmon_collector.py
-------------------
A Sysmon-equivalent standalone event collector for Linux and Windows.
Collects and writes structured JSON logs for:
  - Authentication events      (T1078)
  - System / kernel events     (T1082)
  - Process execution          (T1059)
  - File access / creation     (T1083)
  - Shell command history      (T1059)
  - Sudo / privilege escalation(T1548)
  - Network connections        (T1049)
  - Cron / scheduled tasks     (T1053)
  - Netlink process events     (T1059)  real-time fork/exec/exit/uid-change
  - Fanotify file access       (T1083)  per-process file open/read/write
  - PAM deep auth monitoring   (T1078)  pam_unix/sss/krb5 + wtmp/btmp
  - Procfs enrichment          (T1057)  process snapshots + kernel modules
  - TTY session tracking        (T1078)  utmp binary parse, all users
  - Sensitive file watchlist    (T1552)  SSH keys, cloud creds, /etc/shadow
  - DNS query capture           (T1071)  systemd-resolved / dnsmasq / named
  - USB / mount events          (T1052)  udev netlink + /proc/mounts diff
  - ptrace / debugger detection (T1055)  auditd syscall 101/310/311
  - GUI session monitoring      (T1078)  logind D-Bus or /run/user poll

Linux requirements  : Python 3.8+, root/sudo (for auditd, netlink, fanotify)
                      Optional: auditd, inotify-tools for richer events
Windows requirements: Python 3.8+, pywin32  (pip install pywin32)
                      Run as Administrator for Security + Sysmon channels

Environment variables:
  UEBA_LOG     Path to output JSON log file (default: /home/sadmin/ueba/t1.json)
  UEBA_STDOUT  Set to "1" to also print events to console

Usage:
    python sysmon_collector.py                          # default log path
    python sysmon_collector.py --log /var/log/vm.log    # custom path
    python sysmon_collector.py --interval 3             # poll every 3 s
    python sysmon_collector.py --once                   # single pass (cron)
    python sysmon_collector.py --watch /opt /srv        # extra file-watch dirs (Linux)
"""

import platform, re, os, json, time, logging, argparse, subprocess, threading
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────
# Defaults & environment config
# ─────────────────────────────────────────────────────────────────
_HERE    = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("UEBA_LOG",    "/home/sadmin/ueba/t1.json")
_STDOUT  = os.environ.get("UEBA_STDOUT", "0") == "1"

DEFAULT_LOG_PATH      = LOG_FILE
DEFAULT_POLL_INTERVAL = 2          # seconds
OS                    = platform.system()

# MITRE ATT&CK mappings
MITRE = {
    "auth":    "T1078",   # Valid Accounts
    "kernel":  "T1082",   # System Information Discovery
    "process": "T1059",   # Command and Scripting Interpreter
    "file":    "T1083",   # File and Directory Discovery
    "shell":   "T1059",   # Command and Scripting Interpreter (shell history)
    "sudo":    "T1548",   # Abuse Elevation Control Mechanism
    "network": "T1049",   # System Network Connections Discovery
    "cron":    "T1053",   # Scheduled Task/Job
    "procfs":  "T1057",   # Process Discovery
    "usb":     "T1052",   # Exfiltration over Physical Medium
    "session": "T1078",   # Valid Accounts (TTY/GUI sessions)
}


# ─────────────────────────────────────────────────────────────────
# Shared logger  — one JSON line per event
# ─────────────────────────────────────────────────────────────────
def setup_logger(log_path: str) -> logging.Logger:
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    log = logging.getLogger("sysmon")
    log.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(fh)

    # Console handler — only attached when UEBA_STDOUT=1 or running interactively
    if _STDOUT:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-5s %(message)s", "%H:%M:%S"))
        log.addHandler(ch)
    return log


def emit(log: logging.Logger, category: str, record: dict) -> None:
    """Stamp, serialise, and write one event."""
    record.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    record["category"] = category
    log.debug(json.dumps(record, ensure_ascii=False))
    log.info("cat=%-8s  type=%-22s  %s",
             category,
             record.get("event_type", ""),
             "  ".join(f"{k}={v}" for k, v in record.items()
                       if k not in ("timestamp","category","event_type","raw","mitre_id") and v))


# ─────────────────────────────────────────────────────────────────
# ██████████  L I N U X   C O L L E C T O R S  ██████████
# ─────────────────────────────────────────────────────────────────

class LinuxAuthCollector:
    """Tails /var/log/auth.log for SSH / PAM authentication events."""
    KEYWORDS = ["session opened", "session closed", "Failed password", "Accepted"]

    def __init__(self, log, auth_log="/var/log/auth.log"):
        self.log       = log
        self.auth_log  = auth_log
        self._pos      = 0

    def collect(self):
        try:
            with open(self.auth_log, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    if any(k in line for k in self.KEYWORDS):
                        emit(self.log, "auth", {
                            "event_type": "auth_event",
                            "action":     self._classify(line),
                            "user":       _re(r"for (\S+)", line),
                            "src_ip":     _re(r"from ([\d.]+)", line),
                            "raw":        line.strip()[:512],
                            "mitre_id":   MITRE["auth"],
                        })
                self._pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s — run as root.", self.auth_log)
        except FileNotFoundError:
            self.log.warning("Not found: %s", self.auth_log)
        except Exception as e:
            self.log.error("LinuxAuthCollector: %s", e)

    @staticmethod
    def _classify(line):
        if "Accepted"       in line: return "login_success"
        if "Failed"         in line: return "login_failure"
        if "session opened" in line: return "session_open"
        if "session closed" in line: return "session_close"
        return "auth_misc"


class LinuxKernelCollector:
    """
    Tails /var/log/kern.log (or /var/log/syslog) for kernel / OOM /
    hardware / service-crash events — equivalent to Windows System log.
    """
    SOURCES = ["/var/log/kern.log", "/var/log/syslog", "/var/log/messages"]
    KEYWORDS = [
        "kernel:", "OOM", "Out of memory", "segfault", "panic",
        "Call Trace", "BUG:", "WARNING:", "ERROR:", "ACPI",
        "CPU", "Memory", "oom_kill", "systemd", "failed", "taint",
    ]

    def __init__(self, log):
        self.log  = log
        self._src = self._pick_source()
        self._pos = 0

    def _pick_source(self):
        for s in self.SOURCES:
            if os.path.exists(s):
                return s
        return None

    def collect(self):
        if not self._src:
            return
        try:
            with open(self._src, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    if any(k in line for k in self.KEYWORDS):
                        emit(self.log, "kernel", {
                            "event_type": "kernel_event",
                            "action":     self._classify(line),
                            "subsystem":  _re(r"kernel:\s*\[[\d. ]+\]\s*(\S+)", line),
                            "raw":        line.strip()[:512],
                            "mitre_id":   MITRE["kernel"],
                        })
                self._pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s", self._src)
        except Exception as e:
            self.log.error("LinuxKernelCollector: %s", e)

    @staticmethod
    def _classify(line):
        low = line.lower()
        if "oom" in low or "out of memory" in low: return "oom_kill"
        if "segfault"  in low:                     return "segfault"
        if "panic"     in low:                     return "kernel_panic"
        if "bug:"      in low:                     return "kernel_bug"
        if "warning:"  in low:                     return "kernel_warning"
        if "error:"    in low:                     return "kernel_error"
        if "taint"     in low:                     return "kernel_taint"
        if "failed"    in low:                     return "service_failed"
        return "kernel_misc"


class LinuxProcessCollector:
    """
    Uses /proc polling + optional auditd EXECVE records to capture
    process creation / termination — equivalent to Sysmon Event ID 1.
    Falls back to /proc scanning if auditd is unavailable.
    """
    AUDIT_LOG = "/var/log/audit/audit.log"

    def __init__(self, log):
        self.log        = log
        self._seen_pids = set()
        self._audit_pos = 0
        self._use_audit = os.path.exists(self.AUDIT_LOG)
        if self._use_audit:
            self.log.info("ProcessCollector: using auditd at %s", self.AUDIT_LOG)
        else:
            self.log.info("ProcessCollector: auditd not found, using /proc polling")

    # ── auditd path ──────────────────────────────────────────────
    def _collect_auditd(self):
        try:
            with open(self.AUDIT_LOG, "r", errors="replace") as f:
                f.seek(self._audit_pos)
                for line in f:
                    if "EXECVE" not in line and "type=SYSCALL" not in line:
                        continue
                    if "syscall=59" not in line and "EXECVE" not in line:
                        continue
                    emit(self.log, "process", {
                        "event_type": "process_create",
                        "action":     "exec",
                        "pid":        _re(r"pid=(\d+)", line),
                        "ppid":       _re(r"ppid=(\d+)", line),
                        "uid":        _re(r"\buid=(\d+)", line),
                        "comm":       _re(r'comm="([^"]+)"', line),
                        "exe":        _re(r'exe="([^"]+)"', line),
                        "cmdline":    _re(r'a0="([^"]+)"', line),
                        "raw":        line.strip()[:512],
                        "mitre_id":   MITRE["process"],
                    })
                self._audit_pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s — run as root.", self.AUDIT_LOG)
        except Exception as e:
            self.log.error("ProcessCollector (auditd): %s", e)

    # ── /proc polling path ───────────────────────────────────────
    def _collect_proc(self):
        try:
            current = set()
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                current.add(pid)
                if pid in self._seen_pids:
                    continue
                try:
                    comm    = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()[:256]
                    status  = Path(f"/proc/{pid}/status").read_text(errors="replace")
                    ppid    = _re(r"PPid:\s*(\d+)", status)
                    uid     = _re(r"Uid:\s*(\d+)", status)
                    exe     = ""
                    try:
                        exe = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        pass
                    emit(self.log, "process", {
                        "event_type": "process_create",
                        "action":     "spawn",
                        "pid":        str(pid),
                        "ppid":       ppid,
                        "uid":        uid,
                        "comm":       comm,
                        "exe":        exe,
                        "cmdline":    cmdline,
                        "mitre_id":   MITRE["process"],
                    })
                except (FileNotFoundError, ProcessLookupError):
                    pass  # process already gone

            # report terminated processes
            for gone in self._seen_pids - current:
                emit(self.log, "process", {
                    "event_type": "process_exit",
                    "action":     "exit",
                    "pid":        str(gone),
                    "mitre_id":   MITRE["process"],
                })
            self._seen_pids = current
        except Exception as e:
            self.log.error("ProcessCollector (/proc): %s", e)

    def collect(self):
        if self._use_audit:
            self._collect_auditd()
        else:
            self._collect_proc()


class LinuxFileCollector:
    """
    Watches directories for file-system changes using inotifywait
    (part of inotify-tools). Falls back to mtime-based polling if
    inotifywait is not installed.

    Monitors: create, modify, delete, move, open (sensitive files).
    """
    DEFAULT_WATCH = ["/etc", "/tmp", "/var/tmp", "/home", "/root", "/usr/bin", "/usr/sbin"]
    SENSITIVE_EXT = {".sh", ".py", ".pl", ".rb", ".elf", ".so", ".conf", ".key", ".pem", ".env"}

    def __init__(self, log, extra_dirs=None):
        self.log        = log
        self.watch_dirs = self.DEFAULT_WATCH + (extra_dirs or [])
        self._mtimes    = {}        # path → mtime  (fallback mode)
        self._inotify   = self._check_inotify()
        self._proc      = None      # inotifywait subprocess

        if self._inotify:
            self.log.info("FileCollector: using inotifywait")
            self._start_inotify()
        else:
            self.log.info("FileCollector: inotifywait not found — using mtime polling. "
                          "Install inotify-tools for real-time events.")
            self._snapshot()

    @staticmethod
    def _check_inotify():
        try:
            subprocess.run(["inotifywait", "--version"],
                           capture_output=True, timeout=3)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _start_inotify(self):
        dirs = [d for d in self.watch_dirs if os.path.isdir(d)]
        cmd  = ["inotifywait", "-m", "-r", "--format", "%T %e %w%f",
                "--timefmt", "%Y-%m-%dT%H:%M:%S", "-e",
                "create,modify,delete,moved_from,moved_to,open"] + dirs
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL,
                                          text=True, bufsize=1)
        except Exception as e:
            self.log.error("inotifywait start failed: %s", e)
            self._inotify = False
            self._snapshot()

    def _snapshot(self):
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for root, _, files in os.walk(d):
                    for fn in files:
                        p = os.path.join(root, fn)
                        try:
                            self._mtimes[p] = os.stat(p).st_mtime
                        except OSError:
                            pass
            except PermissionError:
                pass

    # ── inotify read (non-blocking) ──────────────────────────────
    def _collect_inotify(self):
        if not self._proc:
            return
        import select
        try:
            while select.select([self._proc.stdout], [], [], 0)[0]:
                line = self._proc.stdout.readline()
                if not line:
                    break
                parts = line.strip().split(" ", 2)
                if len(parts) < 3:
                    continue
                ts, events, path = parts
                emit(self.log, "file", {
                    "event_type": "file_event",
                    "action":     events.lower().split(",")[0],
                    "path":       path,
                    "ext":        os.path.splitext(path)[1].lower(),
                    "sensitive":  os.path.splitext(path)[1].lower() in self.SENSITIVE_EXT,
                    "timestamp":  ts + "+00:00",
                    "mitre_id":   MITRE["file"],
                })
        except Exception as e:
            self.log.error("FileCollector (inotify): %s", e)

    # ── mtime polling fallback ───────────────────────────────────
    def _collect_poll(self):
        new_mtimes = {}
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for root, _, files in os.walk(d):
                    for fn in files:
                        p = os.path.join(root, fn)
                        try:
                            mt = os.stat(p).st_mtime
                            new_mtimes[p] = mt
                            old = self._mtimes.get(p)
                            if old is None:
                                action = "create"
                            elif mt != old:
                                action = "modify"
                            else:
                                continue
                            emit(self.log, "file", {
                                "event_type": "file_event",
                                "action":     action,
                                "path":       p,
                                "ext":        os.path.splitext(p)[1].lower(),
                                "sensitive":  os.path.splitext(p)[1].lower() in self.SENSITIVE_EXT,
                                "mitre_id":   MITRE["file"],
                            })
                        except OSError:
                            pass
            except PermissionError:
                pass

        # deleted files
        for p in set(self._mtimes) - set(new_mtimes):
            emit(self.log, "file", {
                "event_type": "file_event",
                "action":     "delete",
                "path":       p,
                "ext":        os.path.splitext(p)[1].lower(),
                "sensitive":  os.path.splitext(p)[1].lower() in self.SENSITIVE_EXT,
                "mitre_id":   MITRE["file"],
            })
        self._mtimes = new_mtimes

    def collect(self):
        if self._inotify:
            self._collect_inotify()
        else:
            self._collect_poll()

    def stop(self):
        if self._proc:
            self._proc.terminate()


# ─────────────────────────────────────────────────────────────────
# ██████  L I N U X   A D V A N C E D   C O L L E C T O R S  █████
# ─────────────────────────────────────────────────────────────────

class NetlinkProcessCollector:
    """
    Listens to the Linux kernel Netlink CONNECTOR (CN_IDX_PROC) socket for
    real-time process fork/exec/exit/uid-change events — no kernel module
    or auditd required.

    Kernel struct cn_msg / proc_event layout (little-endian):
      [nlmsghdr 16B][cn_msg 20B][proc_event]

    proc_event.what values:
      0x00000000  PROC_EVENT_NONE
      0x00000001  PROC_EVENT_FORK
      0x00000002  PROC_EVENT_EXEC
      0x00000004  PROC_EVENT_UID
      0x00000040  PROC_EVENT_EXIT

    Requires: root (CAP_NET_ADMIN).
    Falls back gracefully with a warning if unavailable.
    """
    NETLINK_CONNECTOR = 11
    CN_IDX_PROC       = 1
    CN_VAL_PROC       = 1

    # proc_event.what
    PROC_FORK = 0x00000001
    PROC_EXEC = 0x00000002
    PROC_UID  = 0x00000004
    PROC_EXIT = 0x00000040

    # struct sizes
    _NLMSG_HDR  = 16   # nlmsghdr
    _CN_MSG     = 20   # cn_msg header (idx,val,seq,ack,len,flags)
    _PROC_HDR   = 8    # proc_event.what + cpu

    def __init__(self, log):
        self.log    = log
        self._sock  = None
        self._buf   = b""
        self._ready = False
        self._setup()

    def _setup(self):
        import socket, struct
        try:
            sock = socket.socket(socket.AF_NETLINK,
                                 socket.SOCK_DGRAM,
                                 self.NETLINK_CONNECTOR)
            sock.bind((os.getpid(), self.CN_IDX_PROC))
            sock.setblocking(False)

            # send PROC_CN_MCAST_LISTEN (op=1) to subscribe
            # cn_msg: idx=1, val=1, seq=0, ack=0, len=4, flags=0
            import struct as st
            cn_msg  = st.pack("IIIIHH", self.CN_IDX_PROC, self.CN_VAL_PROC,
                              0, 0, 4, 0)
            op      = st.pack("I", 1)   # PROC_CN_MCAST_LISTEN
            nlmsg   = st.pack("IHHII",
                              self._NLMSG_HDR + len(cn_msg) + len(op),
                              0x10, 0, 0, os.getpid())   # NLMSG_DONE
            sock.send(nlmsg + cn_msg + op)
            self._sock  = sock
            self._ready = True
            log = self.log
            log.info("NetlinkProcessCollector: subscribed to CN_PROC events")
        except PermissionError:
            self.log.warning("NetlinkProcessCollector: needs root/CAP_NET_ADMIN — skipping")
        except OSError as e:
            self.log.warning("NetlinkProcessCollector: %s — skipping", e)

    def collect(self):
        if not self._ready:
            return
        import struct, select
        try:
            while select.select([self._sock], [], [], 0)[0]:
                data = self._sock.recv(4096)
                self._parse_event(data, struct)
        except Exception as e:
            self.log.debug("NetlinkProcessCollector recv: %s", e)

    def _parse_event(self, data, struct):
        offset = self._NLMSG_HDR + self._CN_MSG
        if len(data) < offset + self._PROC_HDR:
            return
        what, cpu = struct.unpack_from("II", data, offset)
        offset    += self._PROC_HDR

        try:
            if what == self.PROC_FORK and len(data) >= offset + 16:
                parent_pid, parent_tgid, child_pid, child_tgid = \
                    struct.unpack_from("IIII", data, offset)
                record = {
                    "event_type": "process_fork",
                    "action":     "fork",
                    "pid":        str(child_pid),
                    "ppid":       str(parent_pid),
                    "mitre_id":   MITRE["process"],
                }
                record.update(self._enrich(child_pid))
                emit(self.log, "process", record)

            elif what == self.PROC_EXEC and len(data) >= offset + 8:
                pid, tgid = struct.unpack_from("II", data, offset)
                record = {
                    "event_type": "process_exec",
                    "action":     "exec",
                    "pid":        str(pid),
                    "mitre_id":   MITRE["process"],
                }
                record.update(self._enrich(pid))
                emit(self.log, "process", record)

            elif what == self.PROC_EXIT and len(data) >= offset + 16:
                pid, tgid, exit_code, exit_signal = \
                    struct.unpack_from("IIII", data, offset)
                emit(self.log, "process", {
                    "event_type":  "process_exit",
                    "action":      "exit",
                    "pid":         str(pid),
                    "exit_code":   str(exit_code),
                    "exit_signal": str(exit_signal),
                    "mitre_id":    MITRE["process"],
                })

            elif what == self.PROC_UID and len(data) >= offset + 16:
                pid, tgid, ruid, euid = struct.unpack_from("IIII", data, offset)
                emit(self.log, "sudo", {
                    "event_type": "uid_change",
                    "action":     "uid_change",
                    "pid":        str(pid),
                    "ruid":       str(ruid),
                    "euid":       str(euid),
                    "mitre_id":   MITRE["sudo"],
                })
        except Exception as e:
            self.log.debug("NetlinkProcessCollector parse: %s", e)

    @staticmethod
    def _enrich(pid):
        """Pull comm/exe/cmdline/uid from /proc for a freshly-seen pid."""
        info = {}
        try:
            info["comm"]    = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
            info["cmdline"] = (Path(f"/proc/{pid}/cmdline")
                               .read_bytes().replace(b"\x00", b" ")
                               .decode(errors="replace").strip()[:256])
            status          = Path(f"/proc/{pid}/status").read_text(errors="replace")
            info["ppid"]    = _re(r"PPid:\s*(\d+)", status)
            info["uid"]     = _re(r"Uid:\s*(\d+)", status)
            try:
                info["exe"] = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                pass
        except (FileNotFoundError, ProcessLookupError):
            pass
        return info

    def stop(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


class FanotifyCollector:
    """
    Uses Linux fanotify (via /proc/self/fd + ctypes) for high-fidelity
    file-access monitoring with process context (pid, exe, uid).

    Fanotify gives us:
      FAN_OPEN        — file opened
      FAN_ACCESS      — file read
      FAN_MODIFY      — file written
      FAN_CLOSE_WRITE — file closed after write
      FAN_CREATE      — file/dir created  (requires FAN_REPORT_FID kernel 5.1+)
      FAN_DELETE      — file/dir deleted  (requires FAN_REPORT_FID kernel 5.1+)

    Requires: root (CAP_SYS_ADMIN).
    Falls back gracefully to the existing inotify/mtime collector if
    fanotify is unavailable or the kernel is too old.
    """
    import ctypes as _ct

    # fanotify constants
    FAN_CLOEXEC         = 0x00000001
    FAN_CLASS_NOTIF     = 0x00000000
    FAN_REPORT_FID      = 0x00000200
    FAN_NONBLOCK        = 0x00000002

    FAN_ACCESS          = 0x00000001
    FAN_MODIFY          = 0x00000002
    FAN_CLOSE_WRITE     = 0x00000008
    FAN_OPEN            = 0x00000020
    FAN_CREATE          = 0x00000100
    FAN_DELETE          = 0x00000200
    FAN_ONDIR           = 0x40000000

    FAN_MARK_ADD        = 0x00000001
    FAN_MARK_FILESYSTEM = 0x00000100

    AT_FDCWD            = -100

    # event struct: metadata only (no FID)
    _META_FMT  = "QIHHI"   # event_len, vers, reserved, fd, pid
    _META_SIZE = 24

    WATCH_PATHS = ["/etc", "/tmp", "/var/tmp", "/home", "/root",
                   "/usr/bin", "/usr/sbin", "/var/spool/cron"]
    SENSITIVE_EXT = {".sh", ".py", ".pl", ".rb", ".so", ".conf",
                     ".key", ".pem", ".env", ".bash_history", ".zsh_history"}

    def __init__(self, log):
        self.log    = log
        self._fd    = -1
        self._ready = False
        self._setup()

    def _setup(self):
        import ctypes, ctypes.util, struct
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

            # fanotify_init(flags, event_f_flags)
            fd = libc.fanotify_init(
                self.FAN_CLASS_NOTIF | self.FAN_CLOEXEC | self.FAN_NONBLOCK,
                os.O_RDONLY | os.O_LARGEFILE
            )
            if fd < 0:
                errno = ctypes.get_errno()
                raise OSError(errno, os.strerror(errno))

            mask = (self.FAN_OPEN | self.FAN_MODIFY |
                    self.FAN_CLOSE_WRITE | self.FAN_ACCESS)

            for path in self.WATCH_PATHS:
                if not os.path.isdir(path):
                    continue
                ret = libc.fanotify_mark(
                    fd,
                    self.FAN_MARK_ADD,
                    mask,
                    self.AT_FDCWD,
                    path.encode()
                )
                if ret < 0:
                    self.log.debug("fanotify_mark %s: errno=%d", path,
                                   ctypes.get_errno())

            self._fd    = fd
            self._libc  = libc
            self._ready = True
            self.log.info("FanotifyCollector: watching %s", self.WATCH_PATHS)
        except PermissionError:
            self.log.warning("FanotifyCollector: needs root/CAP_SYS_ADMIN — skipping")
        except OSError as e:
            self.log.warning("FanotifyCollector: %s — skipping (kernel too old?)", e)
        except Exception as e:
            self.log.warning("FanotifyCollector init: %s — skipping", e)

    def collect(self):
        if not self._ready:
            return
        import ctypes, struct, select
        try:
            rlist, _, _ = select.select([self._fd], [], [], 0)
            if not rlist:
                return
            buf = os.read(self._fd, 4096)
            offset = 0
            while offset + self._META_SIZE <= len(buf):
                ev_len, vers, _, fd, pid = struct.unpack_from(
                    self._META_FMT, buf, offset)
                if ev_len == 0:
                    break

                # resolve path from the open fd the kernel gives us
                path = ""
                try:
                    path = os.readlink(f"/proc/self/fd/{fd}")
                except OSError:
                    pass
                finally:
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

                # get process info
                comm, exe, uid_str = "", "", ""
                try:
                    comm    = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
                    exe     = os.readlink(f"/proc/{pid}/exe")
                    status  = Path(f"/proc/{pid}/status").read_text(errors="replace")
                    uid_str = _re(r"Uid:\s*(\d+)", status)
                except Exception:
                    pass

                ext = os.path.splitext(path)[1].lower() if path else ""
                emit(self.log, "file", {
                    "event_type": "file_access",
                    "action":     "fanotify_open",
                    "path":       path,
                    "ext":        ext,
                    "sensitive":  ext in self.SENSITIVE_EXT,
                    "pid":        str(pid),
                    "comm":       comm,
                    "exe":        exe,
                    "uid":        uid_str,
                    "mitre_id":   MITRE["file"],
                })
                offset += ev_len
        except Exception as e:
            self.log.debug("FanotifyCollector read: %s", e)

    def stop(self):
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except Exception:
                pass


class PAMLogCollector:
    """
    Deep PAM / authentication activity collector.
    Goes beyond LinuxAuthCollector by parsing:
      - pam_unix, pam_sss, pam_krb5, pam_ldap lines
      - su / sudo / login / sshd PAM interactions
      - pam_tally / pam_faillock account lockouts
      - pam_env, pam_exec, pam_script (often used in attacks)
      - wtmp / btmp last-login and failed-login records via 'last'/'lastb'

    Sources: /var/log/auth.log  +  /var/log/secure  +  wtmp/btmp snapshots
    """
    SOURCES  = ["/var/log/auth.log", "/var/log/secure"]
    PAM_KEYS = [
        "pam_unix", "pam_sss", "pam_krb5", "pam_ldap",
        "pam_tally", "pam_faillock", "pam_exec", "pam_script",
        "pam_env", "account locked", "account unlocked",
        "authentication failure", "check pass", "user unknown",
        "bad password", "password changed", "new password",
    ]

    def __init__(self, log):
        self.log       = log
        self._src      = next((s for s in self.SOURCES if os.path.exists(s)), None)
        self._pos      = 0
        self._last_wtmp = self._wtmp_snapshot("last")
        self._last_btmp = self._wtmp_snapshot("lastb")
        log.info("PAMLogCollector: src=%s", self._src)

    @staticmethod
    def _wtmp_snapshot(cmd):
        """Run last/lastb and return set of lines for diffing."""
        try:
            out = subprocess.check_output(
                [cmd, "-F", "-w"], stderr=subprocess.DEVNULL,
                timeout=5, text=True, errors="replace"
            )
            return set(out.splitlines())
        except Exception:
            return set()

    def _collect_pam_log(self):
        if not self._src:
            return
        try:
            with open(self._src, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    low = line.lower()
                    if not any(k in low for k in self.PAM_KEYS):
                        continue
                    emit(self.log, "auth", {
                        "event_type": "pam_event",
                        "action":     self._classify(low),
                        "user":       (_re(r"for user (\S+)", line) or
                                       _re(r"user=(\S+)", line) or
                                       _re(r"for (\S+) by", line)),
                        "service":    _re(r"\b(sshd|sudo|su|login|gdm|lightdm)\b", line),
                        "pam_module": _re(r"(pam_\w+)", line),
                        "tty":        _re(r"tty=(\S+)", line),
                        "raw":        line.strip()[:512],
                        "mitre_id":   MITRE["auth"],
                    })
                self._pos = f.tell()
        except PermissionError:
            self.log.warning("PAMLogCollector: permission denied %s", self._src)
        except Exception as e:
            self.log.error("PAMLogCollector: %s", e)

    def _collect_wtmp(self):
        """Diff wtmp/btmp to detect new login/logout/failed records."""
        new_last  = self._wtmp_snapshot("last")
        new_lastb = self._wtmp_snapshot("lastb")

        for line in (new_last - self._last_wtmp):
            parts = line.split()
            if not parts or parts[0] in ("wtmp", ""):
                continue
            emit(self.log, "auth", {
                "event_type": "wtmp_login",
                "action":     "session_record",
                "user":       parts[0] if parts else "",
                "terminal":   parts[1] if len(parts) > 1 else "",
                "src_ip":     parts[2] if len(parts) > 2 else "",
                "raw":        line.strip()[:256],
                "mitre_id":   MITRE["auth"],
            })
        self._last_wtmp = new_last

        for line in (new_lastb - self._last_btmp):
            parts = line.split()
            if not parts or parts[0] in ("btmp", ""):
                continue
            emit(self.log, "auth", {
                "event_type": "btmp_failed_login",
                "action":     "login_failure",
                "user":       parts[0] if parts else "",
                "terminal":   parts[1] if len(parts) > 1 else "",
                "src_ip":     parts[2] if len(parts) > 2 else "",
                "raw":        line.strip()[:256],
                "mitre_id":   MITRE["auth"],
            })
        self._last_btmp = new_lastb

    def collect(self):
        self._collect_pam_log()
        self._collect_wtmp()

    @staticmethod
    def _classify(low):
        if "account locked"          in low: return "account_locked"
        if "account unlocked"        in low: return "account_unlocked"
        if "authentication failure"  in low: return "auth_failure"
        if "password changed"        in low: return "password_changed"
        if "new password"            in low: return "password_change_attempt"
        if "user unknown"            in low: return "unknown_user"
        if "bad password"            in low: return "bad_password"
        if "check pass"              in low: return "pam_check"
        if "pam_exec"                in low: return "pam_exec"
        if "pam_script"              in low: return "pam_script"
        return "pam_misc"


class ProcfsEnrichmentCollector:
    """
    Periodic deep snapshot of /proc for full system inventory and
    process enrichment — equivalent to what htop/ps/osquery do.

    Emits enriched records for:
      - All running processes with full metadata (every snapshot interval)
      - Loaded kernel modules (/proc/modules)
      - Open network sockets per process (/proc/<pid>/net/tcp)
      - File descriptors per process (/proc/<pid>/fd)
      - Memory maps for suspicious processes (/proc/<pid>/maps)

    Designed to run at a slower cadence (every N main polls) to avoid
    flooding the log. Default: emit full snapshot every 30 cycles.
    """
    SNAPSHOT_EVERY = 30   # poll cycles between full snapshots

    def __init__(self, log):
        self.log         = log
        self._cycle      = 0
        self._prev_mods  = set()
        log.info("ProcfsEnrichmentCollector: full snapshot every %d cycles",
                 self.SNAPSHOT_EVERY)

    def collect(self):
        self._cycle += 1
        # Module changes every cycle (cheap)
        self._collect_modules()
        # Full process snapshot at slower cadence
        if self._cycle % self.SNAPSHOT_EVERY == 0:
            self._collect_processes()

    def _collect_processes(self):
        """Emit a snapshot record for every running process."""
        try:
            import pwd
            uid_cache = {}
            def uid_name(uid_str):
                if uid_str not in uid_cache:
                    try:
                        uid_cache[uid_str] = pwd.getpwuid(int(uid_str)).pw_name
                    except Exception:
                        uid_cache[uid_str] = uid_str
                return uid_cache[uid_str]

            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = entry.name
                try:
                    status   = Path(f"/proc/{pid}/status").read_text(errors="replace")
                    cmdline  = (Path(f"/proc/{pid}/cmdline")
                                .read_bytes().replace(b"\x00", b" ")
                                .decode(errors="replace").strip()[:256])
                    comm     = _re(r"Name:\s*(\S+)", status)
                    ppid     = _re(r"PPid:\s*(\d+)", status)
                    uid      = _re(r"Uid:\s*(\d+)", status)
                    threads  = _re(r"Threads:\s*(\d+)", status)
                    vm_rss   = _re(r"VmRSS:\s*(\d+ \w+)", status)
                    exe      = ""
                    try:
                        exe = os.readlink(f"/proc/{pid}/exe")
                    except OSError:
                        pass
                    # count open fds
                    fd_count = 0
                    try:
                        fd_count = len(os.listdir(f"/proc/{pid}/fd"))
                    except OSError:
                        pass

                    emit(self.log, "procfs", {
                        "event_type": "process_snapshot",
                        "action":     "snapshot",
                        "pid":        pid,
                        "ppid":       ppid,
                        "comm":       comm,
                        "exe":        exe,
                        "cmdline":    cmdline,
                        "uid":        uid,
                        "user":       uid_name(uid),
                        "threads":    threads,
                        "vm_rss":     vm_rss,
                        "fd_count":   str(fd_count),
                        "mitre_id":   MITRE["process"],
                    })
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    pass
                except Exception as e:
                    self.log.debug("ProcfsEnrichment pid=%s: %s", pid, e)
        except Exception as e:
            self.log.error("ProcfsEnrichmentCollector: %s", e)

    def _collect_modules(self):
        """Detect kernel module load/unload events via /proc/modules."""
        try:
            content   = Path("/proc/modules").read_text(errors="replace")
            current   = set()
            mod_info  = {}
            for line in content.splitlines():
                parts = line.split()
                if not parts:
                    continue
                name      = parts[0]
                size      = parts[1] if len(parts) > 1 else ""
                ref_count = parts[2] if len(parts) > 2 else ""
                used_by   = parts[3] if len(parts) > 3 else ""
                state     = parts[4] if len(parts) > 4 else ""
                current.add(name)
                mod_info[name] = (size, ref_count, used_by, state)

            # newly loaded modules
            for name in current - self._prev_mods:
                size, refs, used, state = mod_info.get(name, ("","","",""))
                emit(self.log, "kernel", {
                    "event_type": "module_load",
                    "action":     "module_loaded",
                    "module":     name,
                    "size":       size,
                    "ref_count":  refs,
                    "used_by":    used,
                    "state":      state,
                    "mitre_id":   "T1547",   # Boot/Logon Autostart: Kernel Modules
                })

            # unloaded modules
            for name in self._prev_mods - current:
                emit(self.log, "kernel", {
                    "event_type": "module_unload",
                    "action":     "module_unloaded",
                    "module":     name,
                    "mitre_id":   "T1547",
                })

            self._prev_mods = current
        except Exception as e:
            self.log.debug("ProcfsEnrichment modules: %s", e)



# ─────────────────────────────────────────────────────────────────
# ██████  G A P   F I L L E R   C O L L E C T O R S  (Linux)  ████
# ─────────────────────────────────────────────────────────────────

class TTYSessionCollector:
    """
    Tracks terminal session open/close for all users by parsing
    /var/run/utmp as a binary C struct — no extra packages needed.

    ut_type 7 = USER_PROCESS (open), 8 = DEAD_PROCESS (close).
    struct utmp is 384 bytes on 64-bit Linux.
    Emits tty_session_open / tty_session_close with user, tty, pid, src_host.
    MITRE T1078.
    """
    UTMP_PATH    = "/var/run/utmp"
    UTMP_SIZE    = 384
    USER_PROCESS = 7
    DEAD_PROCESS = 8

    def __init__(self, log):
        self.log    = log
        self._seen  = {}
        self._mtime = 0.0
        log.info("TTYSessionCollector: watching %s", self.UTMP_PATH)

    def _parse_utmp(self):
        import struct
        try:
            st = os.stat(self.UTMP_PATH)
        except OSError:
            return
        if st.st_mtime == self._mtime:
            return
        self._mtime = st.st_mtime
        try:
            data = Path(self.UTMP_PATH).read_bytes()
        except (PermissionError, OSError):
            self.log.warning("TTYSessionCollector: cannot read %s", self.UTMP_PATH)
            return
        offset = 0
        while offset + self.UTMP_SIZE <= len(data):
            rec = data[offset: offset + self.UTMP_SIZE]
            offset += self.UTMP_SIZE
            try:
                ut_type = struct.unpack_from("=h", rec, 0)[0]
                ut_pid  = struct.unpack_from("=i", rec, 4)[0]
                ut_line = rec[8:40].rstrip(b"\x00").decode(errors="replace")
                ut_user = rec[44:76].rstrip(b"\x00").decode(errors="replace")
                ut_host = rec[76:332].rstrip(b"\x00").decode(errors="replace")
                tv_sec  = struct.unpack_from("=q", rec, 340)[0]
                login_ts = (datetime.fromtimestamp(tv_sec, tz=timezone.utc).isoformat()
                            if tv_sec > 0 else "")
                yield {
                    "ut_type":  ut_type,
                    "pid":      str(ut_pid),
                    "tty":      ut_line,
                    "user":     ut_user,
                    "src_host": ut_host,
                    "login_ts": login_ts,
                }
            except Exception:
                continue

    def collect(self):
        current_pids = set()
        for rec in self._parse_utmp():
            pid     = rec["pid"]
            ut_type = rec["ut_type"]
            if ut_type == self.USER_PROCESS:
                current_pids.add(pid)
                if pid not in self._seen:
                    self._seen[pid] = rec
                    emit(self.log, "session", {
                        "event_type": "tty_session",
                        "action":     "session_open",
                        "user":       rec["user"],
                        "pid":        pid,
                        "tty":        rec["tty"],
                        "src_host":   rec["src_host"],
                        "login_ts":   rec["login_ts"],
                        "mitre_id":   MITRE["auth"],
                    })
            elif ut_type == self.DEAD_PROCESS:
                if pid in self._seen:
                    old = self._seen.pop(pid)
                    emit(self.log, "session", {
                        "event_type": "tty_session",
                        "action":     "session_close",
                        "user":       old["user"],
                        "pid":        pid,
                        "tty":        old["tty"],
                        "src_host":   old["src_host"],
                        "login_ts":   old["login_ts"],
                        "mitre_id":   MITRE["auth"],
                    })
        for pid in list(self._seen):
            if pid not in current_pids:
                old = self._seen.pop(pid)
                emit(self.log, "session", {
                    "event_type": "tty_session",
                    "action":     "session_close_stale",
                    "user":       old["user"],
                    "pid":        pid,
                    "tty":        old["tty"],
                    "mitre_id":   MITRE["auth"],
                })


class SensitiveFileWatchlist:
    """
    Targeted watchlist for high-value files — credential stores, SSH keys,
    cloud tokens, config files. Supplements FanotifyCollector with semantic
    categorisation. Polls mtime each cycle; no extra packages needed.

    MITRE T1003 (credential dumping), T1552 (unsecured credentials), T1083.
    """
    WATCHLIST = {
        "credential": [
            "/etc/shadow", "/etc/passwd", "/etc/gshadow",
            "/etc/security/opasswd",
        ],
        "ssh_key": [
            "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key",
        ],
        "cloud_creds": [
            "/root/.aws/credentials", "/root/.aws/config",
            "/root/.config/gcloud/credentials.db",
            "/root/.azure/accessTokens.json",
        ],
        "tokens": [
            "/root/.netrc", "/root/.git-credentials",
        ],
        "config": [
            "/etc/sudoers", "/etc/hosts", "/etc/pam.conf",
            "/etc/pam.d/common-auth", "/etc/pam.d/sshd",
            "/etc/ssh/sshd_config",
        ],
    }
    MITRE_MAP = {
        "credential":  "T1003",
        "ssh_key":     "T1552",
        "cloud_creds": "T1552",
        "tokens":      "T1552",
        "config":      "T1083",
        "history":     "T1059",
    }

    def __init__(self, log):
        self.log     = log
        self._mtimes = {}
        self._paths  = {}
        self._build_list()
        log.info("SensitiveFileWatchlist: tracking %d paths", len(self._paths))

    def _build_list(self):
        import pwd
        for category, paths in self.WATCHLIST.items():
            for p in paths:
                self._paths[p] = category
        try:
            for pw in pwd.getpwall():
                if not pw.pw_dir or not os.path.isdir(pw.pw_dir):
                    continue
                home = pw.pw_dir
                for fname in [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
                               ".ssh/authorized_keys"]:
                    self._paths[os.path.join(home, fname)] = "ssh_key"
                for fname in [".aws/credentials", ".netrc", ".git-credentials"]:
                    self._paths[os.path.join(home, fname)] = "tokens"
                for fname in [".bash_history", ".zsh_history"]:
                    self._paths[os.path.join(home, fname)] = "history"
        except Exception:
            pass
        for p in self._paths:
            try:
                self._mtimes[p] = os.stat(p).st_mtime
            except OSError:
                pass

    def collect(self):
        for path, category in self._paths.items():
            try:
                st  = os.stat(path)
                old = self._mtimes.get(path)
                if old is None:
                    self._mtimes[path] = st.st_mtime
                    action = "sensitive_file_created"
                elif st.st_mtime != old:
                    self._mtimes[path] = st.st_mtime
                    action = "sensitive_file_modified"
                else:
                    continue
                emit(self.log, "file", {
                    "event_type": "sensitive_file_access",
                    "action":     action,
                    "path":       path,
                    "category":   category,
                    "severity":   "high",
                    "mitre_id":   self.MITRE_MAP.get(category, MITRE["file"]),
                })
            except FileNotFoundError:
                if path in self._mtimes:
                    del self._mtimes[path]
                    emit(self.log, "file", {
                        "event_type": "sensitive_file_access",
                        "action":     "sensitive_file_deleted",
                        "path":       path,
                        "category":   category,
                        "severity":   "high",
                        "mitre_id":   self.MITRE_MAP.get(category, MITRE["file"]),
                    })
            except (PermissionError, OSError):
                pass


class DNSQueryCollector:
    """
    Captures per-user DNS query activity.
    Sources (tried in order):
      1. journalctl streaming systemd-resolved  (real-time, PID → user)
      2. /var/log/syslog filtered for dnsmasq / named entries
      3. /var/log/named/query.log (BIND)
    MITRE T1071 (Application Layer Protocol: DNS).
    """
    SYSLOG_SOURCES = ["/var/log/syslog", "/var/log/messages"]
    NAMED_LOG      = "/var/log/named/query.log"

    def __init__(self, log):
        self.log        = log
        self._mode      = None
        self._src       = None
        self._pos       = 0
        self._jctl_proc = None
        self._uid_cache = {}
        self._setup()

    def _uid_to_user(self, uid_str):
        if uid_str in self._uid_cache:
            return self._uid_cache[uid_str]
        try:
            import pwd
            name = pwd.getpwuid(int(uid_str)).pw_name
        except Exception:
            name = uid_str
        self._uid_cache[uid_str] = name
        return name

    def _pid_to_user(self, pid_str):
        try:
            status = Path(f"/proc/{pid_str}/status").read_text(errors="replace")
            uid    = _re(r"Uid:\s*(\d+)", status)
            return self._uid_to_user(uid), uid
        except Exception:
            return "", ""

    def _setup(self):
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "systemd-resolved", "-f", "-n", "0",
                 "--output=short-unix", "--no-pager"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
            self._jctl_proc = proc
            self._mode      = "journalctl"
            self.log.info("DNSQueryCollector: streaming systemd-resolved via journalctl")
            return
        except FileNotFoundError:
            pass
        for src in self.SYSLOG_SOURCES:
            if os.path.exists(src):
                self._mode = "syslog"
                self._src  = src
                self.log.info("DNSQueryCollector: tailing %s for DNS entries", src)
                return
        if os.path.exists(self.NAMED_LOG):
            self._mode = "named"
            self._src  = self.NAMED_LOG
            self.log.info("DNSQueryCollector: tailing BIND query log")
            return
        self.log.warning("DNSQueryCollector: no DNS log source found — skipping")

    def _emit_dns(self, hostname, qtype, answer, pid="", src_ip=""):
        if not hostname:
            return
        user, uid = self._pid_to_user(pid) if pid else ("", "")
        emit(self.log, "network", {
            "event_type": "dns_query",
            "action":     "lookup",
            "hostname":   hostname,
            "query_type": qtype,
            "answer":     answer,
            "pid":        pid,
            "user":       user,
            "uid":        uid,
            "src_ip":     src_ip,
            "mitre_id":   "T1071",
        })

    def _parse_line(self, line):
        # systemd-resolved: "Lookup of <host> via <iface> type <A> for PID <n>"
        host = (_re(r"Lookup of (\S+)", line) or
                _re(r"QUERY\s+(\S+)", line) or
                _re(r"question.*name\s+(\S+)", line))
        pid  = _re(r"PID (\d+)", line) or _re(r"pid=(\d+)", line)
        qt   = _re(r"\b(A|AAAA|CNAME|MX|TXT|PTR|SRV)\b", line)
        ans  = _re(r"-[>]?\s*([\d\.a-fA-F:]+)", line)
        # dnsmasq: "query[A] host.com from 1.2.3.4"
        if not host:
            host = _re(r"query\[(?:A|AAAA|PTR|MX|TXT|CNAME)\]\s+(\S+)", line)
            qt   = _re(r"query\[(\w+)\]", line)
            src  = _re(r"from ([\d\.]+)", line)
            ans  = _re(r"is\s+([\d\.a-fA-F:]+)", line)
            self._emit_dns(host, qt, ans, src_ip=src)
        else:
            self._emit_dns(host, qt, ans, pid=pid)

    def _collect_journalctl(self):
        import select
        if not self._jctl_proc:
            return
        try:
            while select.select([self._jctl_proc.stdout], [], [], 0)[0]:
                line = self._jctl_proc.stdout.readline()
                if line:
                    self._parse_line(line)
        except Exception as e:
            self.log.debug("DNSQueryCollector (journalctl): %s", e)

    def _collect_file(self):
        try:
            with open(self._src, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    if any(k in line for k in ("dnsmasq", "named", "resolved", "query[")):
                        self._parse_line(line)
                self._pos = f.tell()
        except Exception as e:
            self.log.debug("DNSQueryCollector (file): %s", e)

    def collect(self):
        if not self._mode:
            return
        if self._mode == "journalctl":
            self._collect_journalctl()
        else:
            self._collect_file()

    def stop(self):
        if self._jctl_proc:
            try:
                self._jctl_proc.terminate()
            except Exception:
                pass


class USBDeviceCollector:
    """
    Detects USB / block device plug-in and removal using
    NETLINK_KOBJECT_UEVENT socket (same mechanism as udevd).
    Optional: uses pyudev if installed for richer metadata.
    Also diffs /proc/mounts for filesystem mount/umount events.
    MITRE T1052 (Exfiltration over Physical Medium), T1025.
    """
    NETLINK_KOBJECT_UEVENT = 15
    _GROUPS                = 1

    def __init__(self, log):
        self.log             = log
        self._sock           = None
        self._use_pyudev     = False
        self._monitor        = None
        self._monitor2       = None
        self._mounts_snap    = self._read_mounts()
        self._setup()

    def _read_mounts(self):
        try:
            lines = Path("/proc/mounts").read_text(errors="replace").splitlines()
            return {tuple(l.split()[:3]) for l in lines if l and not l.startswith("#")}
        except Exception:
            return set()

    def _setup(self):
        try:
            import pyudev
            ctx = pyudev.Context()
            m1  = pyudev.Monitor.from_netlink(ctx)
            m1.filter_by_subsystem("usb")
            m1.start()
            m2  = pyudev.Monitor.from_netlink(ctx)
            m2.filter_by_subsystem("block")
            m2.start()
            self._monitor    = m1
            self._monitor2   = m2
            self._use_pyudev = True
            self.log.info("USBDeviceCollector: using pyudev")
            return
        except ImportError:
            pass
        except Exception as e:
            self.log.debug("USBDeviceCollector pyudev: %s", e)
        import socket
        try:
            sock = socket.socket(socket.AF_NETLINK,
                                 socket.SOCK_RAW,
                                 self.NETLINK_KOBJECT_UEVENT)
            sock.bind((os.getpid(), self._GROUPS))
            sock.setblocking(False)
            self._sock = sock
            self.log.info("USBDeviceCollector: using raw NETLINK_KOBJECT_UEVENT")
        except PermissionError:
            self.log.warning("USBDeviceCollector: needs root — skipping netlink")
        except OSError as e:
            self.log.warning("USBDeviceCollector: %s", e)

    def _emit_dev(self, action, subsystem, devname, devtype, extra=None):
        r = {"event_type": "device_event", "action": action,
             "subsystem": subsystem, "device": devname,
             "devtype": devtype, "mitre_id": "T1052"}
        if extra:
            r.update(extra)
        emit(self.log, "usb", r)

    def _parse_uevent(self, data):
        parts  = data.decode(errors="replace").split("\x00")
        action = parts[0].split("@")[0] if parts else ""
        info   = {"action": action}
        for part in parts[1:]:
            if "=" in part:
                k, _, v = part.partition("=")
                info[k.lower()] = v
        return info

    def _collect_pyudev(self):
        import select
        for mon in [self._monitor, self._monitor2]:
            if not mon:
                continue
            try:
                while select.select([mon], [], [], 0)[0]:
                    dev = mon.poll(timeout=0)
                    if dev:
                        self._emit_dev(
                            dev.action or "", dev.subsystem or "",
                            dev.get("DEVNAME",""), dev.get("DEVTYPE",""),
                            {"vendor": dev.get("ID_VENDOR",""),
                             "model":  dev.get("ID_MODEL",""),
                             "serial": dev.get("ID_SERIAL_SHORT",""),
                             "fstype": dev.get("ID_FS_TYPE","")})
            except Exception as e:
                self.log.debug("USBDeviceCollector pyudev poll: %s", e)

    def _collect_netlink(self):
        import select
        if not self._sock:
            return
        try:
            while select.select([self._sock], [], [], 0)[0]:
                data = self._sock.recv(4096)
                info = self._parse_uevent(data)
                sub  = info.get("subsystem","")
                if sub not in ("usb","block","scsi"):
                    continue
                self._emit_dev(
                    info.get("action",""), sub,
                    info.get("devname",""), info.get("devtype",""),
                    {"vendor": info.get("id_vendor",""),
                     "model":  info.get("id_model",""),
                     "serial": info.get("id_serial_short",""),
                     "fstype": info.get("id_fs_type","")})
        except Exception as e:
            self.log.debug("USBDeviceCollector netlink: %s", e)

    def _collect_mounts(self):
        SKIP = {"proc","sysfs","devtmpfs","cgroup","tmpfs","devpts","cgroup2","bpf"}
        current = self._read_mounts()
        for entry in current - self._mounts_snap:
            dev, mnt, fstype = entry
            if fstype in SKIP:
                continue
            emit(self.log, "usb", {"event_type":"mount_event","action":"mounted",
                 "device":dev,"mountpoint":mnt,"fs_type":fstype,"mitre_id":"T1025"})
        for entry in self._mounts_snap - current:
            dev, mnt, fstype = entry
            if fstype in SKIP:
                continue
            emit(self.log, "usb", {"event_type":"mount_event","action":"unmounted",
                 "device":dev,"mountpoint":mnt,"fs_type":fstype,"mitre_id":"T1025"})
        self._mounts_snap = current

    def collect(self):
        if self._use_pyudev:
            self._collect_pyudev()
        else:
            self._collect_netlink()
        self._collect_mounts()

    def stop(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


class PTraceDetector:
    """
    Detects ptrace / debugger-attach attempts via auditd syscall records.
    Auto-installs auditctl rules for syscalls 101 (ptrace),
    310 (process_vm_readv), 311 (process_vm_writev) at startup.
    MITRE T1055 (Process Injection).
    """
    AUDIT_LOG       = "/var/log/audit/audit.log"
    PTRACE_SYSCALLS = {"101", "310", "311"}

    def __init__(self, log):
        self.log    = log
        self._pos   = 0
        self._ready = False
        self._setup()

    def _setup(self):
        if not os.path.exists(self.AUDIT_LOG):
            self.log.warning("PTraceDetector: auditd not running — skipping")
            return
        self._install_rules()
        self._ready = True
        self.log.info("PTraceDetector: watching auditd for ptrace syscalls")

    def _install_rules(self):
        for syscall in ("ptrace", "process_vm_readv", "process_vm_writev"):
            try:
                subprocess.run(
                    ["auditctl", "-a", "always,exit", "-F", "arch=b64",
                     "-S", syscall, "-k", "ptrace_detect"],
                    capture_output=True, timeout=5)
            except Exception:
                break

    def collect(self):
        if not self._ready:
            return
        try:
            with open(self.AUDIT_LOG, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    if "ptrace_detect" not in line and "SYSCALL" not in line:
                        continue
                    syscall = _re(r"\bsyscall=(\d+)", line)
                    if "ptrace_detect" not in line and syscall not in self.PTRACE_SYSCALLS:
                        continue
                    a0 = _re(r"\ba0=(\S+)", line)
                    if a0 in ("0x10", "16"):
                        action = "ptrace_attach"
                    elif a0 in ("0x1e", "30"):
                        action = "ptrace_seize"
                    elif syscall == "310":
                        action = "process_vm_read"
                    elif syscall == "311":
                        action = "process_vm_write"
                    else:
                        action = "ptrace_misc"
                    emit(self.log, "process", {
                        "event_type": "ptrace_event",
                        "action":     action,
                        "pid":        _re(r"\bpid=(\d+)", line),
                        "ppid":       _re(r"\bppid=(\d+)", line),
                        "uid":        _re(r"\buid=(\d+)", line),
                        "exe":        _re(r'exe="([^"]+)"', line),
                        "syscall":    syscall,
                        "ptrace_req": a0,
                        "severity":   "high",
                        "mitre_id":   "T1055",
                    })
                self._pos = f.tell()
        except PermissionError:
            self.log.warning("PTraceDetector: permission denied on audit log")
        except Exception as e:
            self.log.error("PTraceDetector: %s", e)


class GUISessionCollector:
    """
    Monitors graphical (X11/Wayland) and virtual terminal sessions.
    Approach A: systemd-logind D-Bus SessionNew/SessionRemoved signals
                (requires dbus-python + python-gi).
    Approach B: polls /run/user/<uid>/ directory presence as fallback.
    MITRE T1078 (Valid Accounts — interactive GUI logon).
    """
    def __init__(self, log):
        self.log            = log
        self._mode          = None
        self._events_q      = []
        self._run_user_snap = self._snap_run_user()
        self._setup()

    def _snap_run_user(self):
        try:
            return {e.name for e in os.scandir("/run/user") if e.name.isdigit()}
        except Exception:
            return set()

    def _setup(self):
        if self._try_dbus():
            return
        self._mode = "poll"
        self.log.info("GUISessionCollector: polling /run/user (install dbus-python for D-Bus mode)")

    def _try_dbus(self):
        try:
            import dbus, dbus.mainloop.glib
            from gi.repository import GLib
        except ImportError:
            return False
        try:
            import threading
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            bus = dbus.SystemBus()
            q   = self._events_q

            def on_new(sid, path):
                try:
                    obj   = bus.get_object("org.freedesktop.login1", str(path))
                    iface = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
                    q.append(("open", iface.GetAll("org.freedesktop.login1.Session")))
                except Exception:
                    pass

            def on_removed(sid, path):
                q.append(("close", {"Id": str(sid)}))

            mgr = bus.get_object("org.freedesktop.login1",
                                  "/org/freedesktop/login1")
            mi  = dbus.Interface(mgr, "org.freedesktop.login1.Manager")
            mi.connect_to_signal("SessionNew",     on_new)
            mi.connect_to_signal("SessionRemoved", on_removed)
            t = threading.Thread(target=GLib.MainLoop().run, daemon=True)
            t.start()
            self._mode = "dbus"
            self.log.info("GUISessionCollector: D-Bus logind signals active")
            return True
        except Exception as e:
            self.log.debug("GUISessionCollector dbus: %s", e)
            return False

    def _collect_dbus(self):
        while self._events_q:
            action, props = self._events_q.pop(0)
            if action == "open":
                emit(self.log, "session", {
                    "event_type":   "gui_session",
                    "action":       "session_open",
                    "session_id":   str(props.get("Id","")),
                    "user":         str(props.get("Name","")),
                    "uid":          str(props.get("UserId","")),
                    "session_type": str(props.get("Type","")),
                    "display":      str(props.get("Display","")),
                    "remote":       str(props.get("Remote","")),
                    "remote_host":  str(props.get("RemoteHost","")),
                    "mitre_id":     MITRE["auth"],
                })
            else:
                emit(self.log, "session", {
                    "event_type": "gui_session",
                    "action":     "session_close",
                    "session_id": str(props.get("Id","")),
                    "mitre_id":   MITRE["auth"],
                })

    def _collect_poll(self):
        import pwd
        current = self._snap_run_user()
        for uid_str in current - self._run_user_snap:
            user = ""
            try:
                user = pwd.getpwuid(int(uid_str)).pw_name
            except Exception:
                pass
            emit(self.log, "session", {
                "event_type":   "gui_session",
                "action":       "session_open",
                "uid":          uid_str,
                "user":         user,
                "session_type": "unknown",
                "mitre_id":     MITRE["auth"],
            })
        for uid_str in self._run_user_snap - current:
            emit(self.log, "session", {
                "event_type":   "gui_session",
                "action":       "session_close",
                "uid":          uid_str,
                "session_type": "unknown",
                "mitre_id":     MITRE["auth"],
            })
        self._run_user_snap = current

    def collect(self):
        if self._mode == "dbus":
            self._collect_dbus()
        elif self._mode == "poll":
            self._collect_poll()


# ─────────────────────────────────────────────────────────────────
# ██████████  W I N D O W S   C O L L E C T O R S  ██████████
# ─────────────────────────────────────────────────────────────────

class _WinBase:
    """Shared helpers for all Windows collectors."""
    NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def __init__(self, log):
        self.log     = log
        self._handle = None
        self._w32    = None

    def _open(self, channel):
        try:
            import win32evtlog
            self._w32    = win32evtlog
            self._handle = win32evtlog.SubscribeToEvents(
                channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                None, None)
        except ImportError:
            self.log.error("pywin32 required: pip install pywin32")
            raise SystemExit(1)
        except Exception as e:
            self.log.error("Cannot open channel '%s': %s", channel, e)

    def _next_events(self, n=50):
        if not self._handle:
            return []
        try:
            return self._w32.EvtNext(self._handle, n, 500, 0) or []
        except Exception:
            return []

    def _parse(self, ev):
        import xml.etree.ElementTree as ET
        xml_str = self._w32.EvtRender(ev, self._w32.EvtRenderEventXml)
        root    = ET.fromstring(xml_str)
        eid     = int(root.find(".//e:EventID", self.NS).text)
        ts      = root.find(".//e:TimeCreated", self.NS)
        ts_val  = ts.get("SystemTime") if ts is not None else ""
        fields  = {d.get("Name"): d.text
                   for d in root.findall(".//e:EventData/e:Data", self.NS)
                   if d.get("Name")}
        return eid, ts_val, fields


class WinAuthCollector(_WinBase):
    """Security log: logon / logoff (4624, 4625, 4634, 4647)."""
    ACTION_MAP = {4624:"login_success", 4625:"login_failure",
                  4634:"session_close", 4647:"session_close"}

    def __init__(self, log):
        super().__init__(log)
        self._open("Security")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if eid not in self.ACTION_MAP:
                    continue
                emit(self.log, "auth", {
                    "event_type": "auth_event",
                    "event_id":   eid,
                    "action":     self.ACTION_MAP[eid],
                    "user":       f.get("TargetUserName",""),
                    "domain":     f.get("TargetDomainName",""),
                    "src_ip":     f.get("IpAddress",""),
                    "logon_type": f.get("LogonType",""),
                    "timestamp":  ts,
                    "mitre_id":   MITRE["auth"],
                })
            except Exception as e:
                self.log.debug("WinAuthCollector skip: %s", e)


class WinKernelCollector(_WinBase):
    """System log: service failures, driver errors, BSODs."""
    # Event IDs of interest in the System channel
    EIDS = {
        41,     # Kernel-Power  — unexpected reboot
        1001,   # BugCheck      — BSOD
        7034,   # Service Control Manager — service crashed
        7036,   # SCM           — service state change
        7045,   # SCM           — new service installed (T1543)
        6008,   # EventLog      — unexpected shutdown
        55,     # NTFS          — file system corruption
        129,    # Disk          — reset to device
    }

    def __init__(self, log):
        super().__init__(log)
        self._open("System")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if eid not in self.EIDS:
                    continue
                emit(self.log, "kernel", {
                    "event_type": "system_event",
                    "event_id":   eid,
                    "action":     self._classify(eid),
                    "service":    f.get("param1", f.get("ServiceName","")),
                    "state":      f.get("param2",""),
                    "timestamp":  ts,
                    "mitre_id":   MITRE["kernel"],
                })
            except Exception as e:
                self.log.debug("WinKernelCollector skip: %s", e)

    @staticmethod
    def _classify(eid):
        return {41:"unexpected_reboot", 1001:"bsod",
                7034:"service_crash",  7036:"service_state_change",
                7045:"service_install",6008:"unexpected_shutdown",
                55:"fs_corruption",    129:"disk_error"}.get(eid, "system_misc")


class WinProcessCollector(_WinBase):
    """
    Security log 4688 (process create) + 4689 (process exit).
    Requires: Audit Process Creation enabled in Local Security Policy.
    Optional: Sysmon channel (Microsoft-Windows-Sysmon/Operational) EID 1/5.
    """
    def __init__(self, log):
        super().__init__(log)
        # Try Sysmon first, fall back to Security 4688
        try:
            self._open("Microsoft-Windows-Sysmon/Operational")
            self._mode = "sysmon"
            log.info("ProcessCollector: using Sysmon channel")
        except Exception:
            self._open("Security")
            self._mode = "security"
            log.info("ProcessCollector: using Security 4688/4689")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if self._mode == "sysmon":
                    if eid == 1:
                        emit(self.log, "process", {
                            "event_type":  "process_create",
                            "event_id":    eid,
                            "action":      "spawn",
                            "pid":         f.get("ProcessId",""),
                            "ppid":        f.get("ParentProcessId",""),
                            "user":        f.get("User",""),
                            "image":       f.get("Image",""),
                            "cmdline":     f.get("CommandLine","")[:512],
                            "parent_img":  f.get("ParentImage",""),
                            "hashes":      f.get("Hashes",""),
                            "timestamp":   ts,
                            "mitre_id":    MITRE["process"],
                        })
                    elif eid == 5:
                        emit(self.log, "process", {
                            "event_type": "process_exit",
                            "event_id":   eid,
                            "action":     "exit",
                            "pid":        f.get("ProcessId",""),
                            "image":      f.get("Image",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["process"],
                        })
                else:  # security 4688/4689
                    if eid == 4688:
                        emit(self.log, "process", {
                            "event_type":  "process_create",
                            "event_id":    eid,
                            "action":      "spawn",
                            "pid":         f.get("NewProcessId",""),
                            "ppid":        f.get("ProcessId",""),
                            "user":        f.get("SubjectUserName",""),
                            "image":       f.get("NewProcessName",""),
                            "cmdline":     f.get("CommandLine","")[:512],
                            "parent_img":  f.get("ParentProcessName",""),
                            "timestamp":   ts,
                            "mitre_id":    MITRE["process"],
                        })
                    elif eid == 4689:
                        emit(self.log, "process", {
                            "event_type": "process_exit",
                            "event_id":   eid,
                            "action":     "exit",
                            "pid":        f.get("ProcessId",""),
                            "image":      f.get("ProcessName",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["process"],
                        })
            except Exception as e:
                self.log.debug("WinProcessCollector skip: %s", e)


class WinFileCollector(_WinBase):
    """
    Sysmon EID 11 (FileCreate) + EID 23 (FileDelete) + Security 4663 (file access).
    Falls back gracefully if Sysmon is not installed.
    """
    def __init__(self, log):
        super().__init__(log)
        try:
            self._open("Microsoft-Windows-Sysmon/Operational")
            self._mode = "sysmon"
            log.info("FileCollector: using Sysmon channel (EID 11/23)")
        except Exception:
            self._open("Security")
            self._mode = "security"
            log.info("FileCollector: using Security 4663 — enable Object Access Auditing")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if self._mode == "sysmon":
                    if eid == 11:
                        emit(self.log, "file", {
                            "event_type": "file_event",
                            "event_id":   eid,
                            "action":     "create",
                            "path":       f.get("TargetFilename",""),
                            "image":      f.get("Image",""),
                            "pid":        f.get("ProcessId",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["file"],
                        })
                    elif eid == 23:
                        emit(self.log, "file", {
                            "event_type": "file_event",
                            "event_id":   eid,
                            "action":     "delete",
                            "path":       f.get("TargetFilename",""),
                            "image":      f.get("Image",""),
                            "pid":        f.get("ProcessId",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["file"],
                        })
                else:  # security 4663
                    if eid == 4663:
                        emit(self.log, "file", {
                            "event_type":  "file_event",
                            "event_id":    eid,
                            "action":      "access",
                            "path":        f.get("ObjectName",""),
                            "access_mask": f.get("AccessMask",""),
                            "user":        f.get("SubjectUserName",""),
                            "pid":         f.get("ProcessId",""),
                            "timestamp":   ts,
                            "mitre_id":    MITRE["file"],
                        })
            except Exception as e:
                self.log.debug("WinFileCollector skip: %s", e)


# ─────────────────────────────────────────────────────────────────
# ██████████  U S E R   A C T I V I T Y   C O L L E C T O R S  ██
# ─────────────────────────────────────────────────────────────────

class LinuxShellHistoryCollector:
    """
    Monitors bash/zsh/fish history files for ALL users under /home + /root.
    Tails each history file by inode so renames/rotations are handled.
    Also reads auditd USER_CMD records when available (more reliable than files).

    Captures: command text, user, shell, working-dir (where available).
    """
    AUDIT_LOG  = "/var/log/audit/audit.log"
    HISTORY_FILES = [".bash_history", ".zsh_history", ".local/share/fish/fish_history"]

    def __init__(self, log):
        self.log        = log
        self._positions = {}   # path → (inode, offset)
        self._audit_pos = 0
        self._use_audit = os.path.exists(self.AUDIT_LOG)
        if self._use_audit:
            log.info("ShellHistoryCollector: using auditd USER_CMD records")
        else:
            log.info("ShellHistoryCollector: polling history files under /home + /root")
        self._snapshot_positions()

    # ── helpers ─────────────────────────────────────────────────
    def _home_dirs(self):
        """Yield (username, home_path) for all real users."""
        import pwd
        for pw in pwd.getpwall():
            if pw.pw_dir and os.path.isdir(pw.pw_dir) and pw.pw_uid >= 0:
                yield pw.pw_name, pw.pw_dir

    def _history_paths(self):
        """Yield (user, path) for every history file that exists."""
        for user, home in self._home_dirs():
            for hf in self.HISTORY_FILES:
                p = os.path.join(home, hf)
                if os.path.isfile(p):
                    yield user, p

    def _snapshot_positions(self):
        for user, path in self._history_paths():
            try:
                st = os.stat(path)
                if path not in self._positions:
                    # start at end so we only capture new commands
                    self._positions[path] = (st.st_ino, st.st_size)
            except OSError:
                pass

    # ── auditd path ─────────────────────────────────────────────
    def _collect_auditd(self):
        try:
            with open(self.AUDIT_LOG, "r", errors="replace") as f:
                f.seek(self._audit_pos)
                for line in f:
                    # USER_CMD lines: type=USER_CMD ... cmd=<hex or quoted>
                    if "USER_CMD" not in line and "type=USER_CMD" not in line:
                        continue
                    cmd  = _re(r'cmd="([^"]+)"', line) or _re(r'cmd=([0-9A-Fa-f]+)', line)
                    # auditd may hex-encode the command
                    if re.fullmatch(r'[0-9A-Fa-f]+', cmd):
                        try:
                            cmd = bytes.fromhex(cmd).decode(errors="replace")
                        except Exception:
                            pass
                    emit(self.log, "shell", {
                        "event_type": "shell_command",
                        "action":     "exec",
                        "user":       _re(r'acct="([^"]+)"', line) or _re(r'uid=(\d+)', line),
                        "uid":        _re(r'\bauid=(\d+)', line),
                        "command":    cmd.strip()[:512],
                        "terminal":   _re(r'terminal=(\S+)', line),
                        "mitre_id":   MITRE["shell"],
                    })
                self._audit_pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s", self.AUDIT_LOG)
        except Exception as e:
            self.log.error("ShellHistoryCollector (auditd): %s", e)

    # ── file polling path ────────────────────────────────────────
    def _collect_files(self):
        for user, path in self._history_paths():
            try:
                st  = os.stat(path)
                old_inode, old_off = self._positions.get(path, (None, 0))
                # handle rotation (new inode) or truncation
                if old_inode and st.st_ino != old_inode:
                    old_off = 0
                if st.st_size <= old_off:
                    self._positions[path] = (st.st_ino, old_off)
                    continue
                shell = "bash" if "bash" in path else "zsh" if "zsh" in path else "fish"
                with open(path, "r", errors="replace") as f:
                    f.seek(old_off)
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # zsh extended history: ": <timestamp>:<elapsed>;<cmd>"
                        cmd = re.sub(r'^:\s*\d+:\d+;', '', line).strip()
                        if cmd:
                            emit(self.log, "shell", {
                                "event_type": "shell_command",
                                "action":     "exec",
                                "user":       user,
                                "shell":      shell,
                                "command":    cmd[:512],
                                "source":     path,
                                "mitre_id":   MITRE["shell"],
                            })
                    self._positions[path] = (st.st_ino, f.tell())
            except PermissionError:
                pass
            except Exception as e:
                self.log.error("ShellHistoryCollector (file %s): %s", path, e)

    def collect(self):
        if self._use_audit:
            self._collect_auditd()
        else:
            self._collect_files()


class LinuxSudoCollector:
    """
    Monitors sudo usage and privilege escalation for all users.
    Sources:
      - /var/log/auth.log  (sudo lines)
      - auditd USER_AUTH / USER_ACCT records for su/sudo
      - /var/log/secure    (RHEL/CentOS equivalent)
    Captures: user, target user (run-as), command, success/failure.
    """
    SOURCES  = ["/var/log/auth.log", "/var/log/secure"]
    KEYWORDS = ["sudo:", "su:", "COMMAND=", "authentication failure",
                "sudo: pam_unix", "USER=", "PWD="]

    def __init__(self, log):
        self.log  = log
        self._src = next((s for s in self.SOURCES if os.path.exists(s)), None)
        self._pos = 0
        if self._src:
            log.info("SudoCollector: tailing %s", self._src)
        else:
            log.warning("SudoCollector: no auth log found")

    def collect(self):
        if not self._src:
            return
        try:
            with open(self._src, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    if not any(k in line for k in self.KEYWORDS):
                        continue
                    if "sudo" not in line.lower() and "su:" not in line.lower():
                        continue
                    emit(self.log, "sudo", {
                        "event_type":  "privilege_escalation",
                        "action":      self._classify(line),
                        "user":        _re(r"sudo:\s+(\S+)", line) or _re(r"for user (\S+)", line),
                        "run_as":      _re(r"USER=(\S+)", line),
                        "command":     _re(r"COMMAND=(.+)$", line).strip()[:512],
                        "cwd":         _re(r"PWD=(\S+)", line),
                        "terminal":    _re(r"TTY=(\S+)", line),
                        "raw":         line.strip()[:512],
                        "mitre_id":    MITRE["sudo"],
                    })
                self._pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s — run as root.", self._src)
        except Exception as e:
            self.log.error("SudoCollector: %s", e)

    @staticmethod
    def _classify(line):
        low = line.lower()
        if "incorrect password" in low or "authentication failure" in low:
            return "sudo_failure"
        if "command not allowed" in low or "not in sudoers" in low:
            return "sudo_denied"
        if "command=" in low:
            return "sudo_exec"
        if "su:" in low and "session opened" in low:
            return "su_session_open"
        if "su:" in low and "session closed" in low:
            return "su_session_close"
        return "sudo_misc"


class LinuxNetworkCollector:
    """
    Polls active network connections per user using /proc/net/tcp(6) + /proc/<pid>/net
    combined with /proc/<pid>/status to resolve UID → username.
    Also reads auditd SOCKADDR / SYSCALL connect records when available.

    Emits new connections only (deduplicates by (pid, local, remote) tuple).
    """
    PROC_TCP  = ["/proc/net/tcp", "/proc/net/tcp6"]
    PROC_UDP  = ["/proc/net/udp", "/proc/net/udp6"]
    AUDIT_LOG = "/var/log/audit/audit.log"

    def __init__(self, log):
        self.log        = log
        self._seen      = set()   # (pid, laddr, raddr)
        self._uid_cache = {}      # uid → username
        self._use_audit = os.path.exists(self.AUDIT_LOG)
        self._audit_pos = 0
        if self._use_audit:
            log.info("NetworkCollector: using auditd SOCKADDR records")
        else:
            log.info("NetworkCollector: polling /proc/net/tcp(6)")

    def _uid_to_user(self, uid_str):
        uid = int(uid_str) if uid_str.isdigit() else -1
        if uid in self._uid_cache:
            return self._uid_cache[uid]
        try:
            import pwd
            name = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            name = uid_str
        self._uid_cache[uid] = name
        return name

    @staticmethod
    def _hex_to_addr(hex_addr):
        """Convert /proc/net/tcp hex address:port to dotted notation."""
        try:
            if len(hex_addr) == 13:  # IPv6: 32hex + 4port
                ip_hex, port_hex = hex_addr[:8], hex_addr[9:]
                # little-endian 4 bytes → IPv4
                ip = ".".join(str(int(ip_hex[i:i+2], 16))
                              for i in range(6, -1, -2))
            else:
                ip_hex, port_hex = hex_addr.split(":")
                ip = ".".join(str(int(ip_hex[i:i+2], 16))
                              for i in range(6, -1, -2))
                port_hex = port_hex
            port = int(port_hex, 16)
            return f"{ip}:{port}"
        except Exception:
            return hex_addr

    def _collect_proc_net(self):
        # Build inode → pid mapping
        inode_to_pid = {}
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                fd_dir = f"/proc/{entry.name}/fd"
                try:
                    for fd in os.scandir(fd_dir):
                        try:
                            lnk = os.readlink(fd.path)
                            m   = re.match(r"socket:\[(\d+)\]", lnk)
                            if m:
                                inode_to_pid[int(m.group(1))] = int(entry.name)
                        except OSError:
                            pass
                except (PermissionError, FileNotFoundError):
                    pass
        except Exception:
            pass

        for src in self.PROC_TCP + self.PROC_UDP:
            proto = "tcp" if "tcp" in src else "udp"
            try:
                with open(src, "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 10 or parts[0] == "sl":
                            continue
                        state   = parts[3]
                        # 01=ESTABLISHED, 0A=LISTEN — only report established
                        if state not in ("01", "08"):
                            continue
                        laddr   = self._hex_to_addr(parts[1])
                        raddr   = self._hex_to_addr(parts[2])
                        inode   = int(parts[9])
                        uid_str = parts[7]
                        pid     = inode_to_pid.get(inode, 0)
                        key     = (pid, laddr, raddr)
                        if key in self._seen:
                            continue
                        self._seen.add(key)

                        # resolve process name
                        comm = ""
                        try:
                            comm = Path(f"/proc/{pid}/comm").read_text().strip()
                        except Exception:
                            pass

                        emit(self.log, "network", {
                            "event_type": "network_connection",
                            "action":     "connect",
                            "proto":      proto,
                            "user":       self._uid_to_user(uid_str),
                            "uid":        uid_str,
                            "pid":        str(pid),
                            "comm":       comm,
                            "local":      laddr,
                            "remote":     raddr,
                            "mitre_id":   MITRE["network"],
                        })
            except (FileNotFoundError, PermissionError):
                pass
            except Exception as e:
                self.log.error("NetworkCollector (/proc/net): %s", e)

    def _collect_auditd(self):
        try:
            with open(self.AUDIT_LOG, "r", errors="replace") as f:
                f.seek(self._audit_pos)
                for line in f:
                    if "SOCKADDR" not in line and "type=SOCKADDR" not in line:
                        continue
                    emit(self.log, "network", {
                        "event_type": "network_connection",
                        "action":     "connect",
                        "user":       _re(r'acct="([^"]+)"', line),
                        "uid":        _re(r'\buid=(\d+)', line),
                        "pid":        _re(r'\bpid=(\d+)', line),
                        "saddr":      _re(r'saddr=(\S+)', line),
                        "raw":        line.strip()[:256],
                        "mitre_id":   MITRE["network"],
                    })
                self._audit_pos = f.tell()
        except PermissionError:
            pass
        except Exception as e:
            self.log.error("NetworkCollector (auditd): %s", e)

    def collect(self):
        if self._use_audit:
            self._collect_auditd()
        self._collect_proc_net()   # always run /proc polling for full picture


class LinuxCronCollector:
    """
    Tracks cron job scheduling and execution for all users.
    Sources:
      - /var/log/syslog or /var/log/cron.log  — cron daemon execution logs
      - /var/spool/cron/crontabs/*             — per-user crontab files (snapshot changes)
      - /etc/cron.d/*, /etc/cron.daily/*, etc. — system-wide cron jobs
    Emits both cron_exec (daemon ran a job) and cron_change (crontab modified).
    """
    CRON_LOGS   = ["/var/log/cron.log", "/var/log/syslog", "/var/log/messages"]
    CRON_DIRS   = ["/var/spool/cron/crontabs", "/var/spool/cron"]
    SYSTEM_CRON = ["/etc/cron.d", "/etc/crontab",
                   "/etc/cron.daily", "/etc/cron.hourly",
                   "/etc/cron.weekly", "/etc/cron.monthly"]

    def __init__(self, log):
        self.log        = log
        self._log_src   = next((s for s in self.CRON_LOGS if os.path.exists(s)), None)
        self._log_pos   = 0
        self._cron_snap = {}   # path → (mtime, size)
        self._snapshot_crontabs()
        log.info("CronCollector: log=%s  crontab_dirs=%s",
                 self._log_src, [d for d in self.CRON_DIRS if os.path.isdir(d)])

    def _snapshot_crontabs(self):
        paths = list(self.SYSTEM_CRON)
        for d in self.CRON_DIRS:
            if os.path.isdir(d):
                try:
                    paths += [os.path.join(d, f) for f in os.listdir(d)]
                except PermissionError:
                    pass
        for p in paths:
            try:
                st = os.stat(p)
                self._cron_snap[p] = (st.st_mtime, st.st_size)
            except OSError:
                pass

    # ── cron daemon execution log ────────────────────────────────
    def _collect_log(self):
        if not self._log_src:
            return
        try:
            with open(self._log_src, "r", errors="replace") as f:
                f.seek(self._log_pos)
                for line in f:
                    if "CRON" not in line and "cron" not in line:
                        continue
                    if "CMD" not in line and "session" not in line.lower():
                        continue
                    emit(self.log, "cron", {
                        "event_type": "cron_exec",
                        "action":     "cron_run" if "CMD" in line else "cron_session",
                        "user":       _re(r"for user (\S+)", line) or _re(r"\((\S+)\)", line),
                        "command":    _re(r"CMD \((.+)\)", line).strip()[:512],
                        "raw":        line.strip()[:512],
                        "mitre_id":   MITRE["cron"],
                    })
                self._log_pos = f.tell()
        except PermissionError:
            self.log.warning("Permission denied: %s", self._log_src)
        except Exception as e:
            self.log.error("CronCollector (log): %s", e)

    # ── crontab file change detection ───────────────────────────
    def _collect_crontab_changes(self):
        paths = list(self.SYSTEM_CRON)
        for d in self.CRON_DIRS:
            if os.path.isdir(d):
                try:
                    paths += [os.path.join(d, fn) for fn in os.listdir(d)]
                except PermissionError:
                    pass

        for p in paths:
            try:
                st      = os.stat(p)
                current = (st.st_mtime, st.st_size)
                old     = self._cron_snap.get(p)
                if old is None:
                    action = "crontab_create"
                elif current != old:
                    action = "crontab_modify"
                else:
                    continue
                self._cron_snap[p] = current

                # try to read first non-comment line as a sample
                sample = ""
                try:
                    with open(p, "r", errors="replace") as cf:
                        for ln in cf:
                            ln = ln.strip()
                            if ln and not ln.startswith("#"):
                                sample = ln[:256]
                                break
                except Exception:
                    pass

                user = os.path.basename(p)
                if p.startswith("/etc"):
                    user = "root/system"

                emit(self.log, "cron", {
                    "event_type": "cron_change",
                    "action":     action,
                    "user":       user,
                    "path":       p,
                    "sample":     sample,
                    "mitre_id":   MITRE["cron"],
                })
            except OSError:
                pass

        # detect deleted crontabs
        for p in list(self._cron_snap):
            if not os.path.exists(p):
                emit(self.log, "cron", {
                    "event_type": "cron_change",
                    "action":     "crontab_delete",
                    "user":       os.path.basename(p),
                    "path":       p,
                    "mitre_id":   MITRE["cron"],
                })
                del self._cron_snap[p]

    def collect(self):
        self._collect_log()
        self._collect_crontab_changes()


# ─────────────────────────────────────────────────────────────────
# Windows user-activity collectors
# ─────────────────────────────────────────────────────────────────

class WinShellCollector(_WinBase):
    """
    PowerShell / cmd activity.
    Sources:
      - Security 4688 command line (if process audit enabled)
      - Microsoft-Windows-PowerShell/Operational EID 4103/4104 (script block logging)
      - Windows PowerShell EID 400/800
    """
    PS_EIDS  = {4103, 4104}
    CMD_EIDS = {4688}

    def __init__(self, log):
        super().__init__(log)
        self._ps_handle  = None
        self._sec_handle = None
        try:
            self._open("Microsoft-Windows-PowerShell/Operational")
            self._ps_handle = self._handle
            log.info("WinShellCollector: PowerShell/Operational channel open")
        except Exception:
            log.warning("WinShellCollector: PowerShell channel unavailable; "
                        "enable Script Block Logging via GPO")
        # Security 4688 for cmd.exe
        try:
            import win32evtlog
            self._sec_handle = win32evtlog.SubscribeToEvents(
                "Security", win32evtlog.EvtSubscribeToFutureEvents, None, None)
        except Exception:
            pass

    def collect(self):
        # PowerShell script block events
        if self._ps_handle:
            self._handle = self._ps_handle
            for ev in self._next_events():
                try:
                    eid, ts, f = self._parse(ev)
                    if eid in self.PS_EIDS:
                        emit(self.log, "shell", {
                            "event_type": "shell_command",
                            "event_id":   eid,
                            "action":     "ps_scriptblock" if eid == 4104 else "ps_pipeline",
                            "user":       f.get("UserId",""),
                            "command":    (f.get("ScriptBlockText","") or
                                          f.get("ContextInfo",""))[:512],
                            "path":       f.get("Path",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["shell"],
                        })
                except Exception as e:
                    self.log.debug("WinShellCollector PS skip: %s", e)

        # cmd.exe via Security 4688
        if self._sec_handle:
            self._handle = self._sec_handle
            for ev in self._next_events():
                try:
                    eid, ts, f = self._parse(ev)
                    if eid == 4688 and "cmd.exe" in f.get("NewProcessName","").lower():
                        emit(self.log, "shell", {
                            "event_type": "shell_command",
                            "event_id":   eid,
                            "action":     "cmd_exec",
                            "user":       f.get("SubjectUserName",""),
                            "command":    f.get("CommandLine","")[:512],
                            "image":      f.get("NewProcessName",""),
                            "timestamp":  ts,
                            "mitre_id":   MITRE["shell"],
                        })
                except Exception as e:
                    self.log.debug("WinShellCollector CMD skip: %s", e)


class WinSudoCollector(_WinBase):
    """
    Windows privilege escalation:
      - Security 4672 — special privileges assigned at logon
      - Security 4673 — privileged service called
      - Security 4674 — operation attempted on privileged object
      - Security 4648 — explicit credentials used (runas)
    """
    EIDS = {4672, 4673, 4674, 4648}
    ACTION = {
        4672: "special_privileges_logon",
        4673: "privileged_service_call",
        4674: "privileged_object_op",
        4648: "runas_explicit_creds",
    }

    def __init__(self, log):
        super().__init__(log)
        self._open("Security")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if eid not in self.EIDS:
                    continue
                emit(self.log, "sudo", {
                    "event_type":  "privilege_escalation",
                    "event_id":    eid,
                    "action":      self.ACTION[eid],
                    "user":        f.get("SubjectUserName",""),
                    "domain":      f.get("SubjectDomainName",""),
                    "target_user": f.get("TargetUserName",""),
                    "privileges":  f.get("PrivilegeList","")[:256],
                    "process":     f.get("ProcessName",""),
                    "timestamp":   ts,
                    "mitre_id":    MITRE["sudo"],
                })
            except Exception as e:
                self.log.debug("WinSudoCollector skip: %s", e)


class WinNetworkCollector(_WinBase):
    """
    Network connections per user.
      - Sysmon EID 3 (NetworkConnect) — best source, has user + process
      - Security 5156 (Windows Filtering Platform) — fallback
    """
    def __init__(self, log):
        super().__init__(log)
        try:
            self._open("Microsoft-Windows-Sysmon/Operational")
            self._mode = "sysmon"
            log.info("WinNetworkCollector: using Sysmon EID 3")
        except Exception:
            self._open("Security")
            self._mode = "wfp"
            log.info("WinNetworkCollector: using Security 5156 (WFP)")

    def collect(self):
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if self._mode == "sysmon" and eid == 3:
                    emit(self.log, "network", {
                        "event_type":  "network_connection",
                        "event_id":    eid,
                        "action":      "connect",
                        "user":        f.get("User",""),
                        "image":       f.get("Image",""),
                        "pid":         f.get("ProcessId",""),
                        "proto":       f.get("Protocol",""),
                        "local":       f"{f.get('SourceIp','')}:{f.get('SourcePort','')}",
                        "remote":      f"{f.get('DestinationIp','')}:{f.get('DestinationPort','')}",
                        "dst_host":    f.get("DestinationHostname",""),
                        "initiated":   f.get("Initiated",""),
                        "timestamp":   ts,
                        "mitre_id":    MITRE["network"],
                    })
                elif self._mode == "wfp" and eid == 5156:
                    emit(self.log, "network", {
                        "event_type":  "network_connection",
                        "event_id":    eid,
                        "action":      "connect",
                        "pid":         f.get("ProcessId",""),
                        "proto":       f.get("Protocol",""),
                        "local":       f"{f.get('SourceAddress','')}:{f.get('SourcePort','')}",
                        "remote":      f"{f.get('DestAddress','')}:{f.get('DestPort','')}",
                        "direction":   f.get("Direction",""),
                        "timestamp":   ts,
                        "mitre_id":    MITRE["network"],
                    })
            except Exception as e:
                self.log.debug("WinNetworkCollector skip: %s", e)


class WinCronCollector(_WinBase):
    """
    Scheduled task activity on Windows.
      - Security 4698 — task created
      - Security 4699 — task deleted
      - Security 4700 — task enabled
      - Security 4701 — task disabled
      - Security 4702 — task updated
      - Microsoft-Windows-TaskScheduler/Operational EID 106/140/141/200/201
    """
    SEC_EIDS  = {4698, 4699, 4700, 4701, 4702}
    TASK_EIDS = {106, 140, 141, 200, 201}
    SEC_ACTION = {
        4698: "task_create", 4699: "task_delete",
        4700: "task_enable", 4701: "task_disable", 4702: "task_update",
    }
    TASK_ACTION = {
        106: "task_registered", 140: "task_updated",
        141: "task_deleted",    200: "task_exec_start",
        201: "task_exec_complete",
    }

    def __init__(self, log):
        super().__init__(log)
        self._task_handle = None
        self._sec_handle  = None
        try:
            import win32evtlog
            self._w32 = win32evtlog
            self._sec_handle = win32evtlog.SubscribeToEvents(
                "Security", win32evtlog.EvtSubscribeToFutureEvents, None, None)
            self._task_handle = win32evtlog.SubscribeToEvents(
                "Microsoft-Windows-TaskScheduler/Operational",
                win32evtlog.EvtSubscribeToFutureEvents, None, None)
            log.info("WinCronCollector: Security + TaskScheduler channels open")
        except ImportError:
            log.error("pywin32 required: pip install pywin32")
        except Exception as e:
            log.warning("WinCronCollector: %s", e)

    def _drain(self, handle, action_map):
        if not handle:
            return
        self._handle = handle
        for ev in self._next_events():
            try:
                eid, ts, f = self._parse(ev)
                if eid not in action_map:
                    continue
                emit(self.log, "cron", {
                    "event_type": "scheduled_task",
                    "event_id":   eid,
                    "action":     action_map[eid],
                    "user":       f.get("SubjectUserName", f.get("UserContext","")),
                    "task_name":  f.get("TaskName",""),
                    "task_path":  f.get("TaskContentXml","")[:128] if eid in {4698,4702} else "",
                    "instance":   f.get("InstanceId",""),
                    "timestamp":  ts,
                    "mitre_id":   MITRE["cron"],
                })
            except Exception as e:
                self.log.debug("WinCronCollector skip: %s", e)

    def collect(self):
        self._drain(self._sec_handle,  self.SEC_ACTION)
        self._drain(self._task_handle, self.TASK_ACTION)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
def _re(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else ""


# ─────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────
class SysmonCollector:
    def __init__(self, log, extra_watch_dirs=None):
        self.log        = log
        self.collectors = []

        if OS == "Linux":
            self.collectors = [
                LinuxAuthCollector(log),
                LinuxKernelCollector(log),
                LinuxProcessCollector(log),
                LinuxFileCollector(log, extra_watch_dirs),
                LinuxShellHistoryCollector(log),
                LinuxSudoCollector(log),
                LinuxNetworkCollector(log),
                LinuxCronCollector(log),
                # ── advanced / IPM+ collectors ──
                NetlinkProcessCollector(log),
                FanotifyCollector(log),
                PAMLogCollector(log),
                ProcfsEnrichmentCollector(log),
                # ── gap filler collectors ──
                TTYSessionCollector(log),
                SensitiveFileWatchlist(log),
                DNSQueryCollector(log),
                USBDeviceCollector(log),
                PTraceDetector(log),
                GUISessionCollector(log),
            ]
        elif OS == "Windows":
            self.collectors = [
                WinAuthCollector(log),
                WinKernelCollector(log),
                WinProcessCollector(log),
                WinFileCollector(log),
                WinShellCollector(log),
                WinSudoCollector(log),
                WinNetworkCollector(log),
                WinCronCollector(log),
            ]
        else:
            log.error("Unsupported OS: %s", OS)
            raise SystemExit(1)

    def collect(self):
        for c in self.collectors:
            c.collect()

    def stop(self):
        for c in self.collectors:
            if hasattr(c, "stop"):
                c.stop()


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Sysmon-equivalent collector → structured JSON log file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--log",      default=DEFAULT_LOG_PATH,
                   help=f"Output log file path. Overrides UEBA_LOG env var. (default: {DEFAULT_LOG_PATH})")
    p.add_argument("--interval", type=float, default=DEFAULT_POLL_INTERVAL,
                   help=f"Poll interval seconds (default: {DEFAULT_POLL_INTERVAL}v)")
    p.add_argument("--once",     action="store_true",
                   help="Single collection pass then exit (for cron use)")
    p.add_argument("--watch",    nargs="*", default=[],
                   metavar="DIR",
                   help="Extra directories to watch for file events (Linux)")
    return p.parse_args()


def main():
    args = parse_args()
    log  = setup_logger(args.log)

    log.info("=" * 60)
    log.info("sysmon_collector starting")
    log.info("OS       : %s", OS)
    log.info("Log file : %s", args.log)
    log.info("Interval : %.1f s", args.interval)
    log.info("Collectors: auth | kernel | process | file | shell | sudo | network | cron"
             " | netlink | fanotify | pam | procfs"
             " | tty | sensitive_files | dns | usb | ptrace | gui_session")
    log.info("=" * 60)

    collector = SysmonCollector(log, extra_watch_dirs=args.watch or None)

    if args.once:
        collector.collect()
        log.info("Single-pass complete.")
        return

    log.info("Running — press Ctrl+C to stop.")
    try:
        while True:
            collector.collect()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Stopping collectors...")
        collector.stop()
        log.info("Done.")


if __name__ == "__main__":
    main()
