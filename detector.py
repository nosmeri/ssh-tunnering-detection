import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

import psutil
from scapy.all import TCP, sniff

from config import Config


@dataclass()
class Connections:
    laddr: str
    lport: int
    raddr: str
    rport: int
    pid: int
    cmdline: str
    ts: float = field(default_factory=time.time, compare=False)
    bytes: int = field(default=0, compare=False)
    latest_bytes: int = field(default=0, compare=False)
    small_pkt_count: int = field(default=0, compare=False)
    large_pkt_count: int = field(default=0, compare=False)


@dataclass()
class BannedConnection(Connections):
    score: float = 0.0


def save_attack_log(attacks):
    with open(config.ATTACK_LOG_FILE, "w") as f:
        for atk in attacks:
            line = json.dumps(asdict(atk), ensure_ascii=False)
            f.write(line + "\n")


def load_attack_log():
    if not os.path.exists(config.ATTACK_LOG_FILE):
        return []
    attacks = []
    with open(config.ATTACK_LOG_FILE, "r") as f:
        for i in f.readlines():
            attacks.append(Connections(**json.loads(i)))
    return attacks


def get_ssh_connections():
    ssh_conns = []
    conns = psutil.net_connections(kind="tcp")
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED:
            if c.pid == None:
                continue
            try:
                process = psutil.Process(c.pid)
            except psutil.NoSuchProcess:
                continue
            process_name = process.name()
            if "ssh" not in process_name.lower():
                continue
            if c.raddr.ip in load_whitelist():
                continue
            ssh_conns.append(
                Connections(
                    c.laddr.ip,
                    c.laddr.port,
                    c.raddr.ip,
                    c.raddr.port,
                    c.pid,
                    process.cmdline(),
                )
            )
    return ssh_conns


def cal_score(conn):
    score = 0

    if conn.lport != 22 and conn.rport != 22:
        score += config.PORT_SCORE  # 비표준 포트 점수

    duration = time.time() - conn.ts
    if duration > config.MIN_TIME:
        # 시간 점수를 비선형으로 증가 (로그 스케일 등 고려 가능하나 일단 선형 유지하되 가중치 조절)
        score += (duration / 60) * config.TIME_SCORE

    if conn.cmdline and (
        "-R" in conn.cmdline or "-D" in conn.cmdline or "-L" in conn.cmdline
    ):
        score += config.SSH_CON_SCORE  # SSL 연결 방식 점수

    # 데이터량 점수
    score += (
        (conn.latest_bytes // (1024 * 1024))
        * duration
        // 60
        * config.DATA_SCORE
    )

    # 휴리스틱: 패킷 크기 분석
    # 작은 패킷이 많으면 인터랙티브 터널링 가능성 (Shell 등)
    if conn.small_pkt_count > 20: # 임계값
        score += config.INTERACTIVE_SCORE * (conn.small_pkt_count / 10)
    
    # 큰 패킷이 많으면 벌크 전송 터널링 가능성 (SCP, Port Forwarding 등)
    if conn.large_pkt_count > 5: # 임계값
        score += config.BULK_SCORE * (conn.large_pkt_count / 5)

    return score


def process_packet(packet):
    if packet.haslayer(TCP):
        pkt_len = len(packet)
        for c in ssh_conns:
            if (packet[TCP].sport == c.lport and packet[TCP].dport == c.rport) or (
                packet[TCP].dport == c.lport and packet[TCP].sport == c.rport
            ):
                c.bytes += pkt_len
                c.latest_bytes += pkt_len
                
                # 패킷 크기 분류
                if pkt_len < 100:
                    c.small_pkt_count += 1
                elif pkt_len > 1000:
                    c.large_pkt_count += 1
                    
                # print(f"Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}, Size: {len(packet)}")
                break


# 토큰 로드
def load_token():
    with open(config.TOKEN_FILE, "r") as f:
        return f.read().strip()


# 소켓 준비
def prepare_socket():
    if os.path.exists(config.SOCK_PATH):
        os.remove(config.SOCK_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(config.SOCK_PATH)
    os.chmod(config.SOCK_PATH, 0o660)  # root:group read/write
    os.chown(config.SOCK_PATH, 1000, 1000)
    srv.listen(8)
    return srv


# 길이 접두사가 있는 데이터 읽기/쓰기
def read_prefixed(conn):
    hdr = conn.recv(4)
    if not hdr or len(hdr) < 4:
        return None
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def send_prefixed(conn, obj):
    b = json.dumps(obj, ensure_ascii=False).encode()
    conn.sendall(struct.pack(">I", len(b)) + b)


# HMAC 계산
def compute_hmac_for(obj: Dict[str, Any]) -> str:
    # canonicalize: type+payload sorted, no spaces
    check = {"type": obj["type"], "payload": obj["payload"]}
    cb = json.dumps(check, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(SECRET_TOKEN, cb, hashlib.sha256).hexdigest()


# 화이트리스트 로드/저장
def load_whitelist():
    if not os.path.exists(config.WHITELIST_FILE):
        return []
    with open(config.WHITELIST_FILE, "r") as f:
        return json.load(f)


def save_whitelist(wl):
    tmp = config.WHITELIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(wl, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, config.WHITELIST_FILE)


def append_attack_log(entry):
    line = json.dumps(entry, ensure_ascii=False)
    with open(config.ATTACK_LOG_FILE, "a") as f:
        f.write(line + "\n")


# 요청 처리
def handle_request(obj):
    t = obj.get("type")
    payload = obj.get("payload", {})
    if t == "whitelist_add":
        ip = payload.get("ip").strip()
        if not ip:
            return {"ok": False, "error": "missing ip"}
        with wl_lock:
            wl = load_whitelist()
            if ip in wl:
                return {"ok": True, "result": "already"}
            wl.append(ip)
            save_whitelist(wl)
        return {"ok": True, "result": "added"}

    if t == "whitelist_remove":
        ip = payload.get("ip").strip()
        if not ip:
            return {"ok": False, "error": "missing ip"}
        with wl_lock:
            wl = load_whitelist()
            if ip not in wl:
                return {"ok": True, "result": "not_found"}
            wl.remove(ip)
            save_whitelist(wl)
        return {"ok": True, "result": "removed"}

    if t == "list_whitelist":
        with wl_lock:
            wl = load_whitelist()
        return {"ok": True, "result": wl}

    if t == "get_log":
        attacks = []
        with wl_lock:
            wl = load_whitelist()
        for c in ssh_attacks:
            if c.laddr in wl or c.raddr in wl:
                continue
            attacks.append(asdict(c))

        return {"ok": True, "result": attacks}

    if t == "get_stats":
        with stats_lock:
            return {"ok": True, "result": dict(ssh_stats)}

    if t == "get_banned":
        return {"ok": True, "result": ssh_banned}

    if t == "get_config":
        return {
            "ok": True,
            "result": {
                "mitigation_enabled": config.MITIGATION_ENABLED,
                "critical_score": config.CRITICAL_SCORE,
            },
        }

    if t == "set_config":
        if "mitigation_enabled" in payload:
            config.MITIGATION_ENABLED = bool(payload["mitigation_enabled"])
        if "critical_score" in payload:
            config.CRITICAL_SCORE = float(payload["critical_score"])
        
        # Save to file
        Config.load().MITIGATION_ENABLED = config.MITIGATION_ENABLED
        Config.load().CRITICAL_SCORE = config.CRITICAL_SCORE
        # Note: The above load() creates a new instance, we need to update the file properly.
        # Let's just re-save the current config object.
        # But Config.load() reads from file. We should update the file with current values.
        
        # Re-saving logic:
        # 1. Load current file to preserve other settings (though we have them in memory)
        # 2. Update specific fields
        # 3. Write back
        
        current_cfg = Config.load()
        current_cfg.MITIGATION_ENABLED = config.MITIGATION_ENABLED
        current_cfg.CRITICAL_SCORE = config.CRITICAL_SCORE
        
        with open(config.CFG_PATH if hasattr(config, 'CFG_PATH') else "config.json", "w") as f:
             json.dump(asdict(current_cfg), f, indent=2, ensure_ascii=False)

        return {"ok": True, "result": "updated"}

    return {"ok": False, "error": "unknown type"}


# 클라이언트(conn)의 요청을 처리한 뒤 응답
def client_worker(conn):
    try:
        raw = read_prefixed(conn)
        if raw is None:
            return
        try:
            obj = json.loads(raw.decode())
        except Exception:
            send_prefixed(conn, {"ok": False, "error": "bad json"})
            return

        # verify HMAC(검증)
        if "type" not in obj or "payload" not in obj or "hmac" not in obj:
            send_prefixed(conn, {"ok": False, "error": "invalid format"})
            return
        expected = compute_hmac_for(obj)
        if not hmac.compare_digest(expected, obj["hmac"]):
            send_prefixed(conn, {"ok": False, "error": "auth failed"})
            return

        resp = handle_request(obj)
        send_prefixed(conn, resp)
    finally:
        conn.close()


def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"Killed process {pid}")
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")


# SSH 탐지기
def ssh_detector():
    while True:
        ssh_conns_new = get_ssh_connections()

        for i in range(len(ssh_conns) - 1, -1, -1):
            c = ssh_conns[i]
            c.latest_bytes = 0
            c.small_pkt_count = 0
            c.large_pkt_count = 0
            if c not in ssh_conns_new:
                ssh_conns.pop(i)

        for c in ssh_conns_new:
            c.latest_bytes = 0
            c.small_pkt_count = 0
            c.large_pkt_count = 0
            if c not in ssh_conns:
                ssh_conns.append(c)

        sniff(timeout=config.SNIFF_TIMEOUT, prn=process_packet)

        time.sleep(1)

        print("-" * 30)
        print(f"{len(ssh_conns)} connections")
        
        # Iterate over a copy to safely modify the list if needed
        for c in list(ssh_conns):
            score = cal_score(c)
            print(c)
            print(score)
            
            if score >= config.CRITICAL_SCORE and config.MITIGATION_ENABLED:
                print(f"CRITICAL SCORE DETECTED: {score} for PID {c.pid}. Mitigating...")
                kill_process(c.pid)
                
                # Log banned attack
                banned_entry = BannedConnection(
                    laddr=c.laddr,
                    lport=c.lport,
                    raddr=c.raddr,
                    rport=c.rport,
                    pid=c.pid,
                    cmdline=c.cmdline,
                    ts=time.time(),
                    score=score
                )
                ssh_banned.append(asdict(banned_entry))
                
                if c in ssh_conns:
                    ssh_conns.remove(c)
                continue

            if score >= 100:
                if c not in ssh_attacks:
                    ssh_attacks.append(c)

        save_attack_log(ssh_attacks)


if __name__ == "__main__":

    config = Config.load()

    ssh_attacks = load_attack_log()
    ssh_banned = []
    ssh_conns = ssh_attacks.copy()

    ssh_stats = {
        "total_connections": 0,
        "active_connections": 0,
    }

    wl_lock = threading.Lock()
    stats_lock = threading.Lock()

    SECRET_TOKEN = load_token().encode()

    detector = threading.Thread(target=ssh_detector, daemon=True)
    detector.start()

    srv = prepare_socket()

    print("스캔 시작.")

    try:
        while True:
            conn, _ = srv.accept()
            t = threading.Thread(target=client_worker, args=(conn,), daemon=True)
            t.start()
    finally:
        srv.close()
        try:
            os.remove(config.SOCK_PATH)
        except:
            pass


# 포트, 연결 지속, 데이터 량, -R -D -L
