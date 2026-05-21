#!/usr/bin/env python3
from typing import Any, Dict, Deque, Optional, Tuple, List
import sys
import os
import time
import math
import json
import sqlite3
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import threading
import queue
import collections
import traceback
import datetime
import ipaddress

import regex
from scapy.all import sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR

BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
BLOCK_SCRIPT_PATH: str = os.path.join(BASE_DIR, "scripts", "block_ip.sh")
UNBLOCK_SCRIPT_PATH: str = os.path.join(BASE_DIR, "scripts", "unblock_ip.sh")
RESULT_DIR: str = os.path.join(BASE_DIR, "results")
SIEM_LOG_PATH: str = os.path.join(RESULT_DIR, "siem_dns_detect.json")
DB_PATH: str = os.path.join(RESULT_DIR, "live_soar.db")
WEBHOOK_URL: str = os.environ.get("LIVE_SOAR_WEBHOOK_URL", "")

MAX_QUEUE_SIZE: int = 1000
MAX_STATE_ENTRIES: int = 10000
IP_STATE_MAXLEN: int = 256
WEBHOOK_CACHE_MAXSIZE: int = 10000
FORK_COOLDOWN_TTL: float = 5.0
WEBHOOK_COOLDOWN_TTL: float = 30.0
BLOCK_DURATION_TTL: float = 300.0
BLOCK_MODE: str = os.environ.get("LIVE_SOAR_BLOCK_MODE", "kali_input")


def log_stderr(level: str, message: str) -> None:
    sys.stderr.write("[" + level + "] " + message + "\n")
    sys.stderr.flush()


def compute_entropy(data: str) -> float:
    if not data:
        return 0.0
    import math
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


class SNIHTTPSConnection(urllib.request.http.client.HTTPSConnection):
    def __init__(self, host: str, context: ssl.SSLContext, server_hostname: str, timeout: float = 3.0) -> None:
        super().__init__(host=host, timeout=timeout, context=context)
        self._server_hostname_custom: str = server_hostname

    def connect(self) -> None:
        sock: socket.socket = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self._server_hostname_custom)


class SNIHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, server_hostname: str) -> None:
        super().__init__(context=context)
        self._context_custom: ssl.SSLContext = context
        self._server_hostname_custom: str = server_hostname

    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(self._conn_factory, req)

    def _conn_factory(self, host: str, timeout: float = 300) -> SNIHTTPSConnection:
        return SNIHTTPSConnection(host=host, context=self._context_custom, server_hostname=self._server_hostname_custom, timeout=timeout)


class LiveSOAREngine:
    def __init__(self) -> None:
        self.stop_event: threading.Event = threading.Event()
        self.db_lock: threading.Lock = threading.Lock()
        self.state_lock: threading.Lock = threading.Lock()
        self.file_lock: threading.Lock = threading.Lock()
        self.webhook_lock: threading.Lock = threading.Lock()
        self.fork_lock: threading.Lock = threading.Lock()

        self.analysis_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.webhook_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        self.reconnect_in_progress: bool = False

        self.whitelist_patterns: List[regex.Pattern] = [
            regex.compile(r"(^|\.)google\.com$"),
            regex.compile(r"(^|\.)microsoft\.com$"),
            regex.compile(r"(^|\.)gachon\.ac\.kr$"),
        ]

        self.state: Dict[str, Dict[str, Any]] = {}
        self.blocked_until: Dict[str, float] = {}
        self.fork_cooldown: Dict[str, float] = {}
        self.webhook_cooldown: "collections.OrderedDict[str, float]" = collections.OrderedDict()

        self.analysis_thread: Optional[threading.Thread] = None
        self.webhook_thread: Optional[threading.Thread] = None
        self.ttl_thread: Optional[threading.Thread] = None

    def ensure_dirs(self) -> None:
        os.makedirs(RESULT_DIR, exist_ok=True)

    def init_db(self) -> None:
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=3000;")
        cur: sqlite3.Cursor = self.conn.cursor()
        try:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, is_active INTEGER NOT NULL, blocked_at REAL NOT NULL, unblock_at_mono REAL NOT NULL)"
            )
            self.conn.commit()
        finally:
            try:
                cur.close()
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
        self.cursor = self.conn.cursor()

    def safe_queue_put(self, q: queue.Queue, payload: Dict[str, Any]) -> None:
        try:
            q.put_nowait(payload.copy())
            return
        except queue.Full:
            pass
        try:
            dropped: Any = q.get_nowait()
            _ = dropped
            q.task_done()
        except queue.Empty:
            pass
        try:
            q.put_nowait(payload.copy())
        except queue.Full:
            log_stderr("warn", "queue full, dropped newest payload")

    def normalize_qname(self, qname: Any) -> str:
        if isinstance(qname, bytes):
            decoded: str = qname.decode(errors="ignore")
        else:
            decoded = str(qname).encode(errors="ignore").decode(errors="ignore")
        normalized: str = decoded.lower().rstrip(".")
        return normalized

    def get_subdomain(self, qname: str) -> str:
        parts: List[str] = qname.split(".")
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])

    def process_packet(self, packet: Any) -> None:
        try:
            if len(packet) < 42:
                return
            if packet.haslayer(IPv6):
                return
            if not packet.haslayer(IP):
                return
            if not packet.haslayer(UDP):
                return
            udp_layer: UDP = packet[UDP]
            if int(udp_layer.dport) != 53:
                return
            if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
                return
            dns_layer: DNS = packet[DNS]
            if int(dns_layer.qdcount) < 1:
                return
            if int(dns_layer.qr) != 0:
                return
            qname_raw: Any = packet[DNSQR].qname
            if qname_raw is None:
                return
            qname: str = self.normalize_qname(qname_raw)
            if not qname:
                return
            src_ip: str = str(packet[IP].src)
            payload: Dict[str, Any] = {
                "src_ip": src_ip,
                "qname": qname,
                "mono": float(time.monotonic()),
                "ts": float(time.time()),
            }
            serialized: str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if len(serialized.encode("utf-8")) > 2048:
                payload["qname"] = qname[:256]
            self.safe_queue_put(self.analysis_queue, payload)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()

    def write_siem_log(self, event: Dict[str, Any]) -> None:
        line: str = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        if "\n" in line:
            line = line.replace("\n", " ")
        with self.file_lock:
            try:
                fh = open(SIEM_LOG_PATH, "a", encoding="utf-8")
                try:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    fh.close()
            except OSError:
                log_stderr("error", "siem fsync/write failed")

    def maybe_reconnect_db(self, err: Exception) -> None:
        msg: str = str(err).lower()
        if not ("database is locked" in msg or "disk i/o error" in msg or "database disk image is malformed" in msg):
            return
        with self.db_lock:
            if self.reconnect_in_progress:
                return
            self.reconnect_in_progress = True
        try:
            for _ in range(3):
                try:
                    new_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                    new_conn.execute("PRAGMA journal_mode=WAL;")
                    new_conn.execute("PRAGMA busy_timeout=3000;")
                    with self.db_lock:
                        old_conn = self.conn
                        old_cursor = self.cursor
                        if old_conn is not None:
                            try:
                                old_conn.rollback()
                            except Exception:
                                traceback.print_exc(file=sys.stderr)
                                sys.stderr.flush()
                            try:
                                old_conn.close()
                            except Exception:
                                traceback.print_exc(file=sys.stderr)
                                sys.stderr.flush()
                        if old_cursor is not None:
                            try:
                                old_cursor.close()
                            except Exception:
                                traceback.print_exc(file=sys.stderr)
                                sys.stderr.flush()
                        self.conn = new_conn
                        self.cursor = self.conn.cursor()
                    return
                except Exception:
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                    time.sleep(0.5)
        finally:
            with self.db_lock:
                self.reconnect_in_progress = False

    def analysis_worker(self) -> None:
        while not self.stop_event.is_set():
            got_item: bool = False
            item: Dict[str, Any] = {}
            try:
                try:
                    item = self.analysis_queue.get(timeout=1.0)
                    got_item = True
                except queue.Empty:
                    continue
                src_ip: str = str(item.get("src_ip", ""))
                qname: str = str(item.get("qname", ""))
                now_mono: float = time.monotonic()

                subdomain: str = self.get_subdomain(qname)
                if len(qname.encode("utf-8", "ignore")) > 255:
                    continue
                if subdomain and len(subdomain.encode("utf-8", "ignore")) > 255:
                    continue
                target_string: str = subdomain if (subdomain and len(subdomain) > 0) else qname

                try:
                    for pat in self.whitelist_patterns:
                        if pat.search(qname, timeout=0.01) is not None:
                            continue
                    _ = regex.search(r"^[a-z0-9\-\.]+$", target_string, timeout=0.01)
                except (regex.TimeoutError, TimeoutError, regex.error):
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                    continue

                entropy_val: float = compute_entropy(target_string)
                beacon_stddev: float = 9999.0
                request_count: int = 0
                with self.state_lock:
                    ip_state: Optional[Dict[str, Any]] = self.state.get(src_ip)
                    if ip_state is None:
                        ip_state = {
                            "times": collections.deque(maxlen=IP_STATE_MAXLEN),
                            "last_seen": now_mono,
                        }
                        self.state[src_ip] = ip_state
                    times: Deque[float] = ip_state["times"]
                    times.append(now_mono)
                    ip_state["last_seen"] = now_mono
                    request_count = sum(1 for t in times if now_mono - t <= 10.0)
                    if len(times) >= 6:
                        intervals: List[float] = []
                        idx: int = 1
                        while idx < len(times):
                            intervals.append(times[idx] - times[idx - 1])
                            idx += 1
                        if len(intervals) >= 5:
                            try:
                                mean: float = sum(intervals) / float(len(intervals))
                                var: float = sum((v - mean) * (v - mean) for v in intervals) / float(len(intervals))
                                beacon_stddev = math.sqrt(var)
                                if math.isnan(beacon_stddev) or math.isinf(beacon_stddev):
                                    beacon_stddev = 9999.0
                            except Exception:
                                beacon_stddev = 9999.0
                    self._evict_state_one(now_mono)

                risk_score: int = 0
                if entropy_val > 4.5:
                    risk_score += 2
                if request_count >= 50:
                    risk_score += 3
                if beacon_stddev < 1.0:
                    risk_score += 2
                severity: str = "CRITICAL" if risk_score >= 7 else "INFO"

                event: Dict[str, Any] = {
                    "timestamp": datetime.datetime.utcfromtimestamp(float(item.get("ts", time.time()))).isoformat() + "Z",
                    "src_ip": src_ip,
                    "qname": qname,
                    "entropy": float(entropy_val),
                    "request_count": int(request_count),
                    "beacon_stddev": float(beacon_stddev),
                    "risk_score": int(risk_score),
                    "severity": severity,
                }
                self.write_siem_log(event)

                if severity == "CRITICAL":
                    self.handle_block(src_ip, now_mono)
                    self.safe_queue_put(self.webhook_queue, {
                        "timestamp": event["timestamp"],
                        "src_ip": src_ip,
                        "qname": qname,
                        "risk_score": risk_score,
                        "severity": severity,
                    })
            except Exception as exc:
                self.maybe_reconnect_db(exc)
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                time.sleep(0.1)
            finally:
                if got_item:
                    self.analysis_queue.task_done()

    def _evict_state_one(self, now_mono: float) -> None:
        if len(self.state) < MAX_STATE_ENTRIES:
            return
        for ip_key, st in self.state.items():
            last_seen: float = float(st.get("last_seen", now_mono))
            if now_mono - last_seen > 300.0:
                del self.state[ip_key]
                return
        oldest_ip: Optional[str] = None
        oldest_seen: float = now_mono
        for ip_key, st in self.state.items():
            last_seen = float(st.get("last_seen", now_mono))
            if last_seen <= oldest_seen:
                oldest_seen = last_seen
                oldest_ip = ip_key
        if oldest_ip is not None:
            del self.state[oldest_ip]

    def sanitize_ip(self, src_ip: str) -> str:
        try:
            ipaddress.ip_address(src_ip)
            return src_ip
        except Exception:
            cleaned: str = "".join(ch for ch in src_ip if (ch.isdigit() or ch == "."))
            if not cleaned:
                return ""
            try:
                ipaddress.ip_address(cleaned)
                return cleaned
            except Exception:
                return ""

    def handle_block(self, src_ip: str, now_mono: float) -> None:
        safe_ip: str = self.sanitize_ip(src_ip)
        if not safe_ip:
            return
        if not os.path.exists(BLOCK_SCRIPT_PATH):
            log_stderr("error", "block script missing")
            return
        with self.db_lock:
            if self.conn is None:
                return
            cur: sqlite3.Cursor = self.conn.cursor()
            try:
                cur.execute("SELECT is_active FROM blocked_ips WHERE ip=?", (safe_ip,))
                row: Optional[Tuple[Any, ...]] = cur.fetchone()
                if row is not None and int(row[0]) == 1:
                    return
                with self.fork_lock:
                    prev: float = self.fork_cooldown.get(safe_ip, 0.0)
                    if now_mono - prev < FORK_COOLDOWN_TTL:
                        return
                    self.fork_cooldown[safe_ip] = now_mono
                subprocess.Popen([BLOCK_SCRIPT_PATH, safe_ip, BLOCK_MODE], shell=False, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                unblock_at: float = now_mono + BLOCK_DURATION_TTL
                cur.execute(
                    "INSERT INTO blocked_ips (ip, is_active, blocked_at, unblock_at_mono) VALUES (?,1,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET is_active=1, blocked_at=excluded.blocked_at, unblock_at_mono=excluded.unblock_at_mono",
                    (safe_ip, now_mono, unblock_at),
                )
                self.conn.commit()
                self.blocked_until[safe_ip] = unblock_at
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
                self.maybe_reconnect_db(exc)
            finally:
                try:
                    cur.close()
                except Exception:
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()

    def webhook_worker(self) -> None:
        while not self.stop_event.is_set():
            got_item: bool = False
            item: Dict[str, Any] = {}
            try:
                try:
                    item = self.webhook_queue.get(timeout=1.0)
                    got_item = True
                except queue.Empty:
                    continue
                self.send_webhook(item)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                time.sleep(0.1)
            finally:
                if got_item:
                    self.webhook_queue.task_done()

    def send_webhook(self, payload: Dict[str, Any]) -> None:
        if not WEBHOOK_URL or not WEBHOOK_URL.startswith("https://"):
            return
        src_ip: str = str(payload.get("src_ip", ""))
        qname: str = str(payload.get("qname", ""))
        key: str = src_ip + qname
        now_mono: float = time.monotonic()
        with self.webhook_lock:
            prev: float = self.webhook_cooldown.get(key, 0.0)
            if now_mono - prev < WEBHOOK_COOLDOWN_TTL:
                return
            self.webhook_cooldown[key] = now_mono
            self.webhook_cooldown.move_to_end(key)
            if len(self.webhook_cooldown) > WEBHOOK_CACHE_MAXSIZE:
                expired_key: Optional[str] = None
                for k, tval in self.webhook_cooldown.items():
                    if now_mono - tval > WEBHOOK_COOLDOWN_TTL:
                        expired_key = k
                        break
                if expired_key is not None:
                    del self.webhook_cooldown[expired_key]
                elif len(self.webhook_cooldown) > 0:
                    self.webhook_cooldown.popitem(last=False)

        data_str: str = json.dumps({
            "timestamp": str(payload.get("timestamp", "")),
            "src_ip": src_ip,
            "qname": qname,
            "risk_score": int(payload.get("risk_score", 0)),
            "severity": str(payload.get("severity", "INFO")),
        }, ensure_ascii=False, separators=(",", ":"))
        if len(data_str.encode("utf-8")) > 4096:
            log_stderr("error", "webhook payload too large")
            return

        parsed = urllib.parse.urlparse(WEBHOOK_URL)
        hostname_raw: str = parsed.hostname or ""
        if not hostname_raw:
            return
        canonical_host: str = hostname_raw.encode("idna").decode("ascii")
        infos = socket.getaddrinfo(canonical_host, parsed.port or 443, type=socket.SOCK_STREAM)
        public_ip: Optional[str] = None
        for info in infos:
            addr: str = str(info[4][0])
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_loopback or ip_obj.is_private:
                    return
                if addr == "127.0.0.1" or addr == "::1" or canonical_host == "localhost":
                    return
                public_ip = addr
                break
            except Exception:
                continue
        if public_ip is None:
            return

        path: str = parsed.path if parsed.path else "/"
        if parsed.query:
            path = path + "?" + parsed.query
        target_url: str = "https://" + public_ip + path

        req = urllib.request.Request(target_url, data=data_str.encode("utf-8"), headers={"Content-Type": "application/json", "Host": canonical_host}, method="POST")
        ctx = ssl.create_default_context()
        opener = urllib.request.build_opener(SNIHTTPSHandler(ctx, canonical_host))
        try:
            with opener.open(req, timeout=3.0) as resp:
                _ = resp.read(1)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()

    def ttl_scheduler(self) -> None:
        while not self.stop_event.is_set():
            try:
                now_mono: float = time.monotonic()
                one_ip: Optional[str] = None
                with self.db_lock:
                    if self.conn is not None:
                        cur = self.conn.cursor()
                        try:
                            cur.execute("SELECT ip FROM blocked_ips WHERE is_active=1 AND unblock_at_mono<=? ORDER BY unblock_at_mono ASC LIMIT 1", (now_mono,))
                            row = cur.fetchone()
                            if row is not None:
                                one_ip = str(row[0])
                        finally:
                            try:
                                cur.close()
                            except Exception:
                                traceback.print_exc(file=sys.stderr)
                                sys.stderr.flush()
                if one_ip is not None:
                    self.unblock_ip(one_ip)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                time.sleep(0.1)
            time.sleep(1.0)

    def unblock_ip(self, ip_value: str) -> None:
        if not os.path.exists(UNBLOCK_SCRIPT_PATH):
            log_stderr("error", "unblock script missing")
            return
        safe_ip: str = self.sanitize_ip(ip_value)
        if not safe_ip:
            return
        subprocess.Popen([UNBLOCK_SCRIPT_PATH, safe_ip, BLOCK_MODE], shell=False, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.db_lock:
            if self.conn is None:
                return
            cur = self.conn.cursor()
            try:
                cur.execute("UPDATE blocked_ips SET is_active=0 WHERE ip=?", (safe_ip,))
                self.conn.commit()
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
                self.maybe_reconnect_db(exc)
            finally:
                try:
                    cur.close()
                except Exception:
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()

    def start_workers(self) -> None:
        self.analysis_thread = threading.Thread(target=self.analysis_worker, daemon=True, name="AnalysisWorker")
        self.webhook_thread = threading.Thread(target=self.webhook_worker, daemon=True, name="WebhookWorker")
        self.ttl_thread = threading.Thread(target=self.ttl_scheduler, daemon=True, name="TTLScheduler")
        for t in [self.analysis_thread, self.webhook_thread, self.ttl_thread]:
            t.start()
            time.sleep(0.01)
            if not t.is_alive():
                log_stderr("fatal", "worker failed to start: " + t.name)
                sys.exit(1)

    def run_sniffer_loop(self) -> None:
        while True:
            if self.stop_event.is_set():
                break
            try:
                sniff(
                    iface="any",
                    filter="udp port 53",
                    prn=self.process_packet,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    store=0
                )
            except KeyboardInterrupt:
                self.stop_event.set()
                break
            except PermissionError:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                log_stderr("fatal", "permission denied for sniff")
                sys.exit(1)
            except OSError as exc:
                errno_val: int = int(getattr(exc, "errno", -1) if getattr(exc, "errno", None) is not None else -1)
                if errno_val in (1, 13):
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                    log_stderr("fatal", "sniff permission error")
                    sys.exit(1)
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                time.sleep(3)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                time.sleep(3)

    def shutdown(self) -> None:
        self.stop_event.set()
        time.sleep(0.05)
        if self.cursor is not None:
            try:
                self.cursor.close()
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
        if self.conn is not None:
            try:
                self.conn.rollback()
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
            try:
                self.conn.close()
            except Exception:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
        log_stderr("info", "shutdown complete")


def main() -> None:
    engine: LiveSOAREngine = LiveSOAREngine()
    try:
        try:
            engine.ensure_dirs()
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            log_stderr("fatal", "results directory initialization failed")
            sys.exit(1)
        try:
            engine.init_db()
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            log_stderr("fatal", "sqlite initialization failed")
            sys.exit(1)
        engine.start_workers()
        engine.run_sniffer_loop()
    except KeyboardInterrupt:
        engine.stop_event.set()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        sys.exit(1)
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
