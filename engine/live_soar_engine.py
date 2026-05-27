#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import queue
import signal
import sqlite3
import statistics
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.all import DNS, IP, UDP, sniff  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
NDJSON_PATH = RESULTS_DIR / "siem_dns_detect.json"
DB_PATH = RESULTS_DIR / "live_soar_state.db"
BLOCK_SCRIPT = ROOT / "scripts" / "block_ip.sh"
UNBLOCK_SCRIPT = ROOT / "scripts" / "unblock_ip.sh"
IP_BLACKLIST_FILE = ROOT / "rules" / "ip_blacklist.txt"
DOMAIN_BLACKLIST_FILE = ROOT / "rules" / "domain_blacklist.txt"
DOMAIN_WHITELIST_FILE = ROOT / "rules" / "domain_whitelist.txt"


def load_line_set(path: Path) -> set[str]:
    out: set[str] = set()
    try:
        if not path.exists():
            return out
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            t = ln.strip().lower()
            if not t or t.startswith("#"):
                continue
            out.add(t)
    except Exception:
        return out
    return out


WHITELIST = load_line_set(DOMAIN_WHITELIST_FILE) or {"google.com", "github.com", "microsoft.com"}
BLACKLIST = load_line_set(DOMAIN_BLACKLIST_FILE) or {"attacker.lab", "evil.lab", "malicious.local"}
IP_BLACKLIST = load_line_set(IP_BLACKLIST_FILE)

stop_event = threading.Event()
packet_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
analysis_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
webhook_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)


def monotonic_now() -> float:
    return time.monotonic()


def normalize_qname(qname_raw: Any) -> str:
    try:
        if isinstance(qname_raw, bytes):
            q = qname_raw.decode("utf-8", errors="replace")
        else:
            q = str(qname_raw)
        return q.strip().lower().rstrip(".")
    except Exception:
        return ""


def queue_put_oldest_drop(q: queue.Queue, item: dict[str, Any]) -> None:
    try:
        q.put_nowait(item)
    except queue.Full:
        try:
            q.get_nowait()
        except Exception:
            pass
        try:
            q.put_nowait(item)
        except Exception:
            pass


def process_packet(pkt) -> None:
    # strict non-blocking minimal parser
    try:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return
        dns = pkt[DNS]
        if dns.qr != 0:
            return
        if not dns.qd:
            return
        qd = dns.qd
        if isinstance(qd, list):
            if not qd:
                return
            qd = qd[0]
        qname = normalize_qname(getattr(qd, "qname", ""))
        if not qname:
            return
        event = {
            "mono_ts": monotonic_now(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "is_response": bool(dns.qr == 1),
            "rcode": int(dns.rcode),
            "qname": qname,
            "qtype": int(getattr(qd, "qtype", 0)),
        }
        queue_put_oldest_drop(packet_queue, event)
    except Exception:
        return


@dataclass
class BlockState:
    blocked: bool = False
    unblock_at_mono: float = 0.0
    last_fork_mono: float = 0.0


class StateStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=3000;")
        self._init_schema()
        self.lock = threading.Lock()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                src_ip TEXT PRIMARY KEY,
                blocked INTEGER NOT NULL,
                unblock_at_mono REAL NOT NULL,
                updated_at_mono REAL NOT NULL
            )
            """
        )
        self.conn.commit()

    def upsert_block(self, src_ip: str, blocked: bool, unblock_at_mono: float) -> None:
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO blocks(src_ip, blocked, unblock_at_mono, updated_at_mono)
                VALUES(?,?,?,?)
                ON CONFLICT(src_ip) DO UPDATE SET
                  blocked=excluded.blocked,
                  unblock_at_mono=excluded.unblock_at_mono,
                  updated_at_mono=excluded.updated_at_mono
                """,
                (src_ip, 1 if blocked else 0, unblock_at_mono, monotonic_now()),
            )
            self.conn.commit()

    def get_due_unblocks(self, now_mono: float) -> list[str]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT src_ip FROM blocks WHERE blocked=1 AND unblock_at_mono>0 AND unblock_at_mono<=?",
                (now_mono,),
            )
            return [r[0] for r in cur.fetchall()]


class AnalysisWorker(threading.Thread):
    def __init__(self, store: StateStore):
        super().__init__(daemon=True)
        self.store = store
        self.hist: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=2000))

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    def _base_domain(self, qname: str) -> str:
        parts = [p for p in qname.split(".") if p]
        if len(parts) < 2:
            return qname
        return ".".join(parts[-2:])

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                ev = packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                continue
            try:
                src_ip = ev["src_ip"]
                qname = ev["qname"]
                now_m = float(ev["mono_ts"])
                base = self._base_domain(qname)

                # whitelist drop
                if base in WHITELIST:
                    continue

                self.hist[src_ip].append(ev)
                window = [x for x in self.hist[src_ip] if now_m - float(x["mono_ts"]) <= 10.0 and not x["is_response"]]

                risk = 0
                reasons: list[str] = []

                ent = self._entropy(qname)
                if ent > 4.5:
                    risk += 2
                    reasons.append("entropy>4.5")

                if len(window) >= 50:
                    risk += 3
                    reasons.append("qps_burst_10s>=50")

                if len(window) >= 3:
                    stamps = [float(x["mono_ts"]) for x in window]
                    intervals = [b - a for a, b in zip(stamps[:-1], stamps[1:]) if b - a >= 0]
                    if len(intervals) >= 2:
                        stddev = statistics.pstdev(intervals)
                        if stddev < 1.0:
                            risk += 2
                            reasons.append("interval_stddev<1.0")

                if base in BLACKLIST:
                    risk += 4
                    reasons.append("blacklist")
                if src_ip in IP_BLACKLIST:
                    risk += 7
                    reasons.append("ip_blacklist")

                severity = "CRITICAL" if risk >= 7 else "INFO"
                out = {
                    "ts_epoch": time.time(),
                    "mono_ts": now_m,
                    "src_ip": src_ip,
                    "dst_ip": ev["dst_ip"],
                    "qname": qname,
                    "base_domain": base,
                    "rcode": ev["rcode"],
                    "risk_score": risk,
                    "severity": severity,
                    "reasons": reasons,
                }
                queue_put_oldest_drop(analysis_queue, out)
                if severity == "CRITICAL":
                    queue_put_oldest_drop(webhook_queue, out)
            except Exception:
                continue


class WebhookWorker(threading.Thread):
    def __init__(self, store: StateStore, block_ttl_sec: float = 60.0):
        super().__init__(daemon=True)
        self.store = store
        self.block_ttl_sec = block_ttl_sec
        self.block_state: dict[str, BlockState] = defaultdict(BlockState)

    def _can_fork(self, src_ip: str, now_m: float) -> bool:
        st = self.block_state[src_ip]
        return (now_m - st.last_fork_mono) >= 5.0

    def _mark_fork(self, src_ip: str, now_m: float) -> None:
        st = self.block_state[src_ip]
        st.last_fork_mono = now_m

    def _block(self, src_ip: str, now_m: float) -> None:
        st = self.block_state[src_ip]
        if st.blocked:
            return
        if not self._can_fork(src_ip, now_m):
            return
        try:
            subprocess.run(["bash", str(BLOCK_SCRIPT), src_ip, "kali_input"], check=False)
        except Exception:
            pass
        self._mark_fork(src_ip, now_m)
        st.blocked = True
        st.unblock_at_mono = now_m + self.block_ttl_sec
        self.store.upsert_block(src_ip, True, st.unblock_at_mono)

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                alert = webhook_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                continue
            try:
                if alert.get("severity") == "CRITICAL":
                    self._block(str(alert["src_ip"]), monotonic_now())
            except Exception:
                continue


class TTLScheduler(threading.Thread):
    def __init__(self, store: StateStore, webhook_worker: WebhookWorker):
        super().__init__(daemon=True)
        self.store = store
        self.webhook_worker = webhook_worker

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                now_m = monotonic_now()
                due = self.store.get_due_unblocks(now_m)
                for src_ip in due:
                    st = self.webhook_worker.block_state[src_ip]
                    if now_m - st.last_fork_mono < 5.0:
                        continue
                    try:
                        subprocess.run(["bash", str(UNBLOCK_SCRIPT), src_ip, "kali_input"], check=False)
                    except Exception:
                        pass
                    st.last_fork_mono = now_m
                    st.blocked = False
                    st.unblock_at_mono = 0.0
                    self.store.upsert_block(src_ip, False, 0.0)
                time.sleep(0.5)
            except Exception:
                time.sleep(0.5)


class NDJSONWriter(threading.Thread):
    def run(self) -> None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        while not stop_event.is_set():
            try:
                row = analysis_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                continue
            try:
                with NDJSON_PATH.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            except Exception:
                continue


def _install_signal_handlers() -> None:
    def _handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _install_signal_handlers()
    store = StateStore(DB_PATH)

    analysis_worker = AnalysisWorker(store)
    webhook_worker = WebhookWorker(store)
    ttl_scheduler = TTLScheduler(store, webhook_worker)
    ndjson_writer = NDJSONWriter()

    analysis_worker.start()
    webhook_worker.start()
    ttl_scheduler.start()
    ndjson_writer.start()

    try:
        sniff(
            iface="any",
            filter="udp port 53",
            prn=process_packet,
            stop_filter=lambda _: stop_event.is_set(),
            store=0,
        )
    except Exception:
        stop_event.set()
    finally:
        stop_event.set()
        for t in (analysis_worker, webhook_worker, ttl_scheduler, ndjson_writer):
            try:
                t.join(timeout=2.0)
            except Exception:
                pass


if __name__ == "__main__":
    main()
