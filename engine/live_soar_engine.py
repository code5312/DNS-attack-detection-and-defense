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

import yaml
from scapy.all import DNS, IP, UDP, sniff  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
CFG_PATH = ROOT / "config" / "settings.yaml"


def load_cfg() -> dict:
    if CFG_PATH.exists():
        return yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
    return {}


CFG = load_cfg()
LIVE = CFG.get("live", {})
BL = CFG.get("blacklist", {})
RESP = CFG.get("response", {})
TH = CFG.get("thresholds", {})

RESULTS_DIR = ROOT / "results"
NDJSON_PATH = ROOT / LIVE.get("ndjson_output", "results/siem_dns_detect.json")
DB_PATH = ROOT / LIVE.get("state_db", "results/live_soar_state.db")
BLOCK_SCRIPT = ROOT / "scripts" / "block_ip.sh"
UNBLOCK_SCRIPT = ROOT / "scripts" / "unblock_ip.sh"
IP_BLACKLIST_FILE = ROOT / BL.get("ip_file", "rules/ip_blacklist.txt")
DOMAIN_BLACKLIST_FILE = ROOT / BL.get("domain_file", "rules/domain_blacklist.txt")
DOMAIN_WHITELIST_FILE = ROOT / BL.get("whitelist_file", "rules/domain_whitelist.txt")


def load_line_set(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        t = ln.strip().lower()
        if t and not t.startswith("#"):
            out.add(t)
    return out


WHITELIST = load_line_set(DOMAIN_WHITELIST_FILE)
BLACKLIST = load_line_set(DOMAIN_BLACKLIST_FILE) or {"attacker.lab", "evil.lab", "malicious.local"}
IP_BLACKLIST = load_line_set(IP_BLACKLIST_FILE)

stop_event = threading.Event()
packet_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
analysis_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
webhook_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)


def monotonic_now() -> float:
    return time.monotonic()


def normalize_qname(qname_raw: Any) -> str:
    if isinstance(qname_raw, bytes):
        q = qname_raw.decode("utf-8", errors="replace")
    else:
        q = str(qname_raw)
    return q.strip().lower().rstrip(".")


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
    try:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:
            return
        qd = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
        qname = normalize_qname(getattr(qd, "qname", ""))
        if not qname:
            return
        event = {
            "mono_ts": monotonic_now(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
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
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=3000;")
        self.conn.execute("CREATE TABLE IF NOT EXISTS blocks(src_ip TEXT PRIMARY KEY, blocked INTEGER, unblock_at_mono REAL, updated_at_mono REAL)")
        self.conn.commit()
        self.lock = threading.Lock()

    def upsert_block(self, src_ip: str, blocked: bool, unblock_at_mono: float) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO blocks(src_ip,blocked,unblock_at_mono,updated_at_mono) VALUES(?,?,?,?) ON CONFLICT(src_ip) DO UPDATE SET blocked=excluded.blocked, unblock_at_mono=excluded.unblock_at_mono, updated_at_mono=excluded.updated_at_mono",
                (src_ip, 1 if blocked else 0, unblock_at_mono, monotonic_now()),
            )
            self.conn.commit()

    def get_due_unblocks(self, now_mono: float) -> list[str]:
        with self.lock:
            rows = self.conn.execute("SELECT src_ip FROM blocks WHERE blocked=1 AND unblock_at_mono>0 AND unblock_at_mono<=?", (now_mono,)).fetchall()
            return [r[0] for r in rows]


class AnalysisWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.hist: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=1000))
        self.last_seen: dict[str, float] = {}

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    @staticmethod
    def _domain_parts(qname: str) -> tuple[str, str]:
        p = [x for x in qname.split('.') if x]
        if len(p) < 2:
            return "", qname
        return '.'.join(p[:-2]), '.'.join(p[-2:])

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                ev = packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            src_ip = ev["src_ip"]
            qname = ev["qname"]
            now_m = float(ev["mono_ts"])
            sub, base = self._domain_parts(qname)
            self.last_seen[src_ip] = now_m

            risk = 0
            reasons: list[str] = []
            whitelisted = base in WHITELIST
            if whitelisted:
                out = {"ts_epoch": time.time(), "mono_ts": now_m, "src_ip": src_ip, "dst_ip": ev["dst_ip"], "qname": qname, "base_domain": base, "risk_score": 0, "severity": "INFO", "reasons": ["whitelist"]}
                queue_put_oldest_drop(analysis_queue, out)
                continue

            self.hist[src_ip].append(ev)
            window = [x for x in self.hist[src_ip] if now_m - float(x["mono_ts"]) <= 10.0]

            ent = self._entropy(sub if sub else qname)
            if ent > float(TH.get("max_entropy", 4.5)):
                risk += 2
                reasons.append("entropy>4.5")
            if len(window) >= int(TH.get("query_count_10s", 50)):
                risk += 3
                reasons.append("qps_burst_10s")
            if len(window) >= 3:
                stamps = [float(x["mono_ts"]) for x in window]
                intervals = [b - a for a, b in zip(stamps[:-1], stamps[1:]) if b - a >= 0]
                if len(intervals) >= 2 and statistics.pstdev(intervals) < 1.0:
                    risk += 2
                    reasons.append("interval_stddev<1")
            if base in BLACKLIST:
                risk += 7
                reasons.append("blacklist_hit")
            if src_ip in IP_BLACKLIST:
                risk += 7
                reasons.append("ip_blacklist")

            severity = "CRITICAL" if risk >= 7 else "INFO"
            out = {"ts_epoch": time.time(), "mono_ts": now_m, "src_ip": src_ip, "dst_ip": ev["dst_ip"], "qname": qname, "base_domain": base, "risk_score": risk, "severity": severity, "reasons": reasons}
            queue_put_oldest_drop(analysis_queue, out)
            if severity == "CRITICAL":
                queue_put_oldest_drop(webhook_queue, out)

            # idle eviction
            for ip, t in list(self.last_seen.items()):
                if now_m - t > 120:
                    self.hist.pop(ip, None)
                    self.last_seen.pop(ip, None)


class WebhookWorker(threading.Thread):
    def __init__(self, store: StateStore):
        super().__init__(daemon=True)
        self.store = store
        self.block_state: dict[str, BlockState] = defaultdict(BlockState)
        self.lock = threading.Lock()
        self.block_ttl_sec = float(RESP.get("block_ttl_seconds", 60))
        self.block_mode = str(RESP.get("block_mode", "kali_input"))

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                alert = webhook_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            src_ip = str(alert.get("src_ip", ""))
            now_m = monotonic_now()
            with self.lock:
                st = self.block_state[src_ip]
                if st.blocked or now_m - st.last_fork_mono < 5.0:
                    continue
                try:
                    subprocess.run(["bash", str(BLOCK_SCRIPT), src_ip, self.block_mode], check=False)
                except Exception:
                    pass
                st.blocked = True
                st.last_fork_mono = now_m
                st.unblock_at_mono = now_m + self.block_ttl_sec
                self.store.upsert_block(src_ip, True, st.unblock_at_mono)


class TTLScheduler(threading.Thread):
    def __init__(self, store: StateStore, webhook: WebhookWorker):
        super().__init__(daemon=True)
        self.store = store
        self.webhook = webhook

    def run(self) -> None:
        while not stop_event.is_set():
            now_m = monotonic_now()
            for src_ip in self.store.get_due_unblocks(now_m):
                with self.webhook.lock:
                    st = self.webhook.block_state[src_ip]
                    if now_m - st.last_fork_mono < 5.0:
                        continue
                    try:
                        subprocess.run(["bash", str(UNBLOCK_SCRIPT), src_ip, self.webhook.block_mode], check=False)
                    except Exception:
                        pass
                    st.blocked = False
                    st.unblock_at_mono = 0.0
                    st.last_fork_mono = now_m
                    self.store.upsert_block(src_ip, False, 0.0)
            time.sleep(0.5)


class NDJSONWriter(threading.Thread):
    def run(self) -> None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        with NDJSON_PATH.open("a", encoding="utf-8") as f:
            last_flush = monotonic_now()
            while not stop_event.is_set():
                try:
                    row = analysis_queue.get(timeout=0.5)
                except queue.Empty:
                    row = None
                if row is not None:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                now = monotonic_now()
                if now - last_flush > 1.0:
                    f.flush()
                    last_flush = now


def _install_signal_handlers() -> None:
    def _handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _install_signal_handlers()
    store = StateStore(DB_PATH)
    aw = AnalysisWorker()
    ww = WebhookWorker(store)
    ts = TTLScheduler(store, ww)
    nw = NDJSONWriter()
    aw.start(); ww.start(); ts.start(); nw.start()
    try:
        sniff(iface=str(LIVE.get("iface", "any")), filter=str(LIVE.get("bpf_filter", "udp port 53")), prn=process_packet, stop_filter=lambda _: stop_event.is_set(), store=0)
    except Exception:
        stop_event.set()
    finally:
        stop_event.set()
        for t in (aw, ww, ts, nw):
            t.join(timeout=2.0)


if __name__ == "__main__":
    main()
