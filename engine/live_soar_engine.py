#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import queue
import signal
import sqlite3
import statistics
import subprocess
import sys
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

sys.path.insert(0, str(ROOT / "scripts"))
from playbook import has_effective_action, load_playbook, match_actions, severity_from_score, write_notification  # noqa: E402


def load_cfg() -> dict:
    if CFG_PATH.exists():
        return yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
    return {}


CFG = load_cfg()
LIVE = CFG.get("live", {})
BL = CFG.get("blacklist", {})
RESP = CFG.get("response", {})
TH = CFG.get("thresholds", {})
RISK_LEVELS = CFG.get("risk_levels", {})

RESULTS_DIR = ROOT / "results"
NDJSON_PATH = ROOT / LIVE.get("ndjson_output", "results/siem_dns_detect.json")
DB_PATH = ROOT / LIVE.get("state_db", "results/live_soar_state.db")
NOTIFY_LOG_PATH = RESULTS_DIR / "notifications.log"
BLOCK_SCRIPT = ROOT / "scripts" / "block_ip.sh"
UNBLOCK_SCRIPT = ROOT / "scripts" / "unblock_ip.sh"
IP_BLACKLIST_FILE = ROOT / BL.get("ip_file", "rules/ip_blacklist.txt")
DOMAIN_BLACKLIST_FILE = ROOT / BL.get("domain_file", "rules/domain_blacklist.txt")
DOMAIN_WHITELIST_FILE = ROOT / BL.get("whitelist_file", "rules/domain_whitelist.txt")
PLAYBOOK_PATH = ROOT / RESP.get("playbook_path", "playbooks/dns_tunneling_response.yaml")
PLAYBOOK_RULES = load_playbook(PLAYBOOK_PATH)


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
action_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)


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
    unblock_at_epoch: float = 0.0
    last_fork_mono: float = 0.0


class StateStore:
    def __init__(self, db_path: Path):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=3000;")
        self.conn.execute("CREATE TABLE IF NOT EXISTS blocks(src_ip TEXT PRIMARY KEY, blocked INTEGER, unblock_at_epoch REAL, updated_at_epoch REAL)")
        self._migrate_legacy_schema()
        self.conn.commit()
        self.lock = threading.Lock()

    def _migrate_legacy_schema(self) -> None:
        # Older DBs stored a time.monotonic() value, which is meaningless
        # after a process/host restart. Drop that stale state rather than
        # let TTL comparisons silently never fire (or fire immediately).
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(blocks)")}
        if "unblock_at_mono" in cols and "unblock_at_epoch" not in cols:
            self.conn.execute("DROP TABLE blocks")
            self.conn.execute(
                "CREATE TABLE blocks(src_ip TEXT PRIMARY KEY, blocked INTEGER, unblock_at_epoch REAL, updated_at_epoch REAL)"
            )

    def upsert_block(self, src_ip: str, blocked: bool, unblock_at_epoch: float) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO blocks(src_ip,blocked,unblock_at_epoch,updated_at_epoch) VALUES(?,?,?,?) ON CONFLICT(src_ip) DO UPDATE SET blocked=excluded.blocked, unblock_at_epoch=excluded.unblock_at_epoch, updated_at_epoch=excluded.updated_at_epoch",
                (src_ip, 1 if blocked else 0, unblock_at_epoch, time.time()),
            )
            self.conn.commit()

    def get_due_unblocks(self, now_epoch: float) -> list[str]:
        with self.lock:
            rows = self.conn.execute("SELECT src_ip FROM blocks WHERE blocked=1 AND unblock_at_epoch>0 AND unblock_at_epoch<=?", (now_epoch,)).fetchall()
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
                out = {"ts_epoch": time.time(), "mono_ts": now_m, "src_ip": src_ip, "dst_ip": ev["dst_ip"], "qname": qname, "base_domain": base, "risk_score": 0, "severity": "NORMAL", "reasons": ["whitelist"], "actions": []}
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

            severity = severity_from_score(risk, RISK_LEVELS)
            matched_actions = match_actions(severity, PLAYBOOK_RULES)
            out = {
                "ts_epoch": time.time(), "mono_ts": now_m, "src_ip": src_ip, "dst_ip": ev["dst_ip"],
                "qname": qname, "base_domain": base, "risk_score": risk, "severity": severity,
                "reasons": reasons, "actions": matched_actions,
            }
            queue_put_oldest_drop(analysis_queue, out)
            if has_effective_action(matched_actions):
                queue_put_oldest_drop(action_queue, out)

            # idle eviction
            for ip, t in list(self.last_seen.items()):
                if now_m - t > 120:
                    self.hist.pop(ip, None)
                    self.last_seen.pop(ip, None)


class ActionWorker(threading.Thread):
    """Playbook이 매칭한 액션(block_ip/notify/...)을 실제로 실행하는 워커.

    한 src_ip에 대한 실행은 5초 쿨다운(last_fork_mono)으로 묶여 있다 — block_ip뿐
    아니라 notify도 매 패킷마다 쏟아지지 않도록 액션 종류와 무관하게 공통 적용한다.
    다만 "이미 차단됨(st.blocked)"은 block_ip 재실행만 막을 뿐 notify까지 막지는
    않는다 — 차단 중에도 계속 시도하는 공격에 대한 알림은 계속 남아야 한다.
    """

    def __init__(self, store: StateStore):
        super().__init__(daemon=True)
        self.store = store
        self.block_state: dict[str, BlockState] = defaultdict(BlockState)
        self.lock = threading.Lock()
        self.block_ttl_sec = float(RESP.get("block_ttl_seconds", 60))
        self.block_mode = str(RESP.get("block_mode", "kali_input"))

    def _run_block_ip(self, src_ip: str, params: dict, st: BlockState) -> None:
        mode = str(params.get("mode", self.block_mode))
        ttl = float(params.get("ttl_seconds", self.block_ttl_sec))
        try:
            subprocess.run(["bash", str(BLOCK_SCRIPT), src_ip, mode], check=False)
        except Exception:
            pass
        st.blocked = True
        st.unblock_at_epoch = time.time() + ttl
        self.store.upsert_block(src_ip, True, st.unblock_at_epoch)

    def run(self) -> None:
        while not stop_event.is_set():
            try:
                alert = action_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            src_ip = str(alert.get("src_ip", ""))
            severity = str(alert.get("severity", ""))
            qname = str(alert.get("qname", ""))
            actions = alert.get("actions") or []
            now_m = monotonic_now()
            with self.lock:
                st = self.block_state[src_ip]
                if now_m - st.last_fork_mono < 5.0:
                    continue
                st.last_fork_mono = now_m
                for action in actions:
                    a_type = action.get("type")
                    if a_type == "block_ip":
                        if not st.blocked:
                            self._run_block_ip(src_ip, action, st)
                    elif a_type == "notify":
                        write_notification(
                            NOTIFY_LOG_PATH, severity, src_ip, "live",
                            qname=qname, channel=str(action.get("channel", "log")),
                        )
                    # log_only 및 알 수 없는 타입: 추가 동작 없음


class TTLScheduler(threading.Thread):
    def __init__(self, store: StateStore, action_worker: ActionWorker):
        super().__init__(daemon=True)
        self.store = store
        self.action_worker = action_worker

    def run(self) -> None:
        while not stop_event.is_set():
            now_m = monotonic_now()
            for src_ip in self.store.get_due_unblocks(time.time()):
                with self.action_worker.lock:
                    st = self.action_worker.block_state[src_ip]
                    if now_m - st.last_fork_mono < 5.0:
                        continue
                    try:
                        subprocess.run(["bash", str(UNBLOCK_SCRIPT), src_ip, self.action_worker.block_mode], check=False)
                    except Exception:
                        pass
                    st.blocked = False
                    st.unblock_at_epoch = 0.0
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
    ac = ActionWorker(store)
    ts = TTLScheduler(store, ac)
    nw = NDJSONWriter()
    aw.start(); ac.start(); ts.start(); nw.start()
    try:
        sniff(iface=str(LIVE.get("iface", "any")), filter=str(LIVE.get("bpf_filter", "udp port 53")), prn=process_packet, stop_filter=lambda _: stop_event.is_set(), store=0)
    except Exception:
        stop_event.set()
    finally:
        stop_event.set()
        for t in (aw, ac, ts, nw):
            t.join(timeout=2.0)


if __name__ == "__main__":
    main()
