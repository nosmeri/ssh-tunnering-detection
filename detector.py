import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Tuple

import psutil
from scapy.all import TCP, sniff

from config import Config


@dataclass()
class Connections:
    """
    SSH 연결 정보를 저장하는 데이터 클래스입니다.

    Attributes:
        laddr (str): 로컬 IP 주소.
        lport (int): 로컬 포트 번호.
        raddr (str): 원격 IP 주소.
        rport (int): 원격 포트 번호.
        pid (int): 프로세스 ID.
        cmdline (str): 프로세스 실행 명령어.
        ts (float): 연결 생성 시간 (timestamp).
        bytes (int): 총 전송 바이트 수.
        latest_bytes (int): 최근 측정 주기 동안의 전송 바이트 수.
        small_pkt_count (int): 작은 패킷(100바이트 미만) 개수.
        large_pkt_count (int): 큰 패킷(1000바이트 초과) 개수.
    """
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
    """
    차단된 SSH 연결 정보를 저장하는 데이터 클래스입니다.

    Attributes:
        score (float): 차단 당시의 위험도 점수.
    """
    score: float = 0.0


def save_attack_log(attacks):
    """
    공격 로그를 파일에 저장합니다.

    Args:
        attacks (list[Connections]): 저장할 공격 연결 목록.
    """
    with open(config.ATTACK_LOG_FILE, "w") as f:
        for atk in attacks:
            line = json.dumps(asdict(atk), ensure_ascii=False)
            f.write(line + "\n")


def load_attack_log():
    """
    파일에서 공격 로그를 로드합니다.

    Returns:
        list[Connections]: 로드된 공격 연결 목록.
    """
    if not os.path.exists(config.ATTACK_LOG_FILE):
        return []
    attacks = []
    with open(config.ATTACK_LOG_FILE, "r") as f:
        for i in f.readlines():
            attacks.append(Connections(**json.loads(i)))
    return attacks


def get_ssh_connections() -> Dict[Tuple[str, int, str, int], Connections]:
    """
    현재 시스템의 활성 SSH 연결을 수집합니다.

    Returns:
        Dict[Tuple[str, int, str, int], Connections]: (laddr, lport, raddr, rport)를 키로 하는 연결 정보 딕셔너리.
    """
    ssh_conns_dict = {}
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
            
            conn_obj = Connections(
                c.laddr.ip,
                c.laddr.port,
                c.raddr.ip,
                c.raddr.port,
                c.pid,
                process.cmdline(),
            )
            ssh_conns_dict[(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)] = conn_obj
            
    return ssh_conns_dict


def cal_score(conn):
    """
    연결의 위험도 점수를 계산합니다.

    Args:
        conn (Connections): 점수를 계산할 연결 객체.

    Returns:
        float: 계산된 위험도 점수.
    """
    score = 0

    if conn.lport != 22 and conn.rport != 22:
        score += config.PORT_SCORE  # 비표준 포트 점수

    duration = time.time() - conn.ts
    if duration > config.MIN_TIME:
        # User requested non-linear increase. Using 1.5 power for milder growth than quadratic.
        score += ((duration / 60) ** 1.5) * config.TIME_SCORE

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

    # 작은 패킷이 많으면 인터랙티브 터널링 가능성 (Shell 등)
    if conn.small_pkt_count > 20: # 임계값
        score += config.INTERACTIVE_SCORE * (conn.small_pkt_count / 10)
    
    # 큰 패킷이 많으면 벌크 전송 터널링 가능성 (SCP, Port Forwarding 등)
    if conn.large_pkt_count > 5: # 임계값
        score += config.BULK_SCORE * (conn.large_pkt_count / 5)

    return score


def process_packet(packet):
    """
    캡처된 패킷을 처리하여 연결 통계를 업데이트합니다.

    Args:
        packet (scapy.packet.Packet): 캡처된 패킷.
    """
    if packet.haslayer(TCP):
        pkt_len = len(packet)
        
        # O(1) lookup using dictionary
        # Try both directions
        src_ip = packet[TCP].options[0][1] if False else packet[0][1].src # Scapy structure varies, safer to use IP layer
        # Wait, packet[IP] is safer.
        if not packet.haslayer("IP"):
            return

        src = packet["IP"].src
        dst = packet["IP"].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        # Key format: (laddr, lport, raddr, rport)
        # Check forward: src=laddr, sport=lport, dst=raddr, dport=rport
        c = ssh_conns.get((src, sport, dst, dport))
        
        # Check reverse: dst=laddr, dport=lport, src=raddr, sport=rport
        if not c:
            c = ssh_conns.get((dst, dport, src, sport))
            
        if c:
            c.bytes += pkt_len
            c.latest_bytes += pkt_len
            
            # 패킷 크기 분류
            if pkt_len < 100:
                c.small_pkt_count += 1
            elif pkt_len > 1000:
                c.large_pkt_count += 1


def load_token():
    """
    인증 토큰을 파일에서 로드합니다.

    Returns:
        str: 로드된 토큰 문자열.
    """
    with open(config.TOKEN_FILE, "r") as f:
        return f.read().strip()


def prepare_socket():
    """
    Unix 도메인 소켓을 생성하고 준비합니다.

    Returns:
        socket.socket: 생성된 소켓 객체.
    """
    if os.path.exists(config.SOCK_PATH):
        os.remove(config.SOCK_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(config.SOCK_PATH)
    os.chmod(config.SOCK_PATH, 0o660)  # root:group read/write
    os.chown(config.SOCK_PATH, 1000, 1000)
    srv.listen(8)
    return srv


def read_prefixed(conn):
    """
    길이 접두사가 있는 데이터를 소켓에서 읽습니다.

    Args:
        conn (socket.socket): 데이터를 읽을 소켓.

    Returns:
        bytes: 읽은 데이터. 실패 시 None.
    """
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
    """
    객체를 JSON으로 직렬화하고 길이 접두사를 붙여 소켓으로 전송합니다.

    Args:
        conn (socket.socket): 데이터를 보낼 소켓.
        obj (Any): 전송할 객체.
    """
    b = json.dumps(obj, ensure_ascii=False).encode()
    conn.sendall(struct.pack(">I", len(b)) + b)


def compute_hmac_for(obj: Dict[str, Any]) -> str:
    """
    주어진 객체에 대한 HMAC 서명을 계산합니다.

    Args:
        obj (Dict[str, Any]): 서명할 객체.

    Returns:
        str: 계산된 HMAC 16진수 문자열.
    """
    # canonicalize: type+payload sorted, no spaces
    check = {"type": obj["type"], "payload": obj["payload"]}
    cb = json.dumps(check, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(SECRET_TOKEN, cb, hashlib.sha256).hexdigest()


def load_whitelist():
    """
    화이트리스트를 파일에서 로드합니다.

    Returns:
        list: 화이트리스트 IP 목록.
    """
    if not os.path.exists(config.WHITELIST_FILE):
        return []
    with open(config.WHITELIST_FILE, "r") as f:
        return json.load(f)


def save_whitelist(wl):
    """
    화이트리스트를 파일에 저장합니다.

    Args:
        wl (list): 저장할 화이트리스트 IP 목록.
    """
    tmp = config.WHITELIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(wl, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, config.WHITELIST_FILE)


def append_attack_log(entry):
    """
    공격 로그 파일에 새로운 항목을 추가합니다.

    Args:
        entry (dict): 추가할 로그 항목.
    """
    line = json.dumps(entry, ensure_ascii=False)
    with open(config.ATTACK_LOG_FILE, "a") as f:
        f.write(line + "\n")


def handle_request(obj):
    """
    클라이언트 요청을 처리하고 결과를 반환합니다.

    Args:
        obj (dict): 요청 객체.

    Returns:
        dict: 처리 결과 응답 객체.
    """
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


def client_worker(conn):
    """
    클라이언트 연결을 처리하는 워커 함수입니다.

    Args:
        conn (socket.socket): 클라이언트 소켓.
    """
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
    """
    지정된 PID의 프로세스를 강제 종료합니다.

    Args:
        pid (int): 종료할 프로세스 ID.
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"Killed process {pid}")
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")


def ssh_detector():
    """
    SSH 연결을 지속적으로 모니터링하고 분석하는 메인 루프입니다.
    """
    global ssh_conns, ssh_attacks, ssh_banned # Need to modify global dict
    while True:
        ssh_conns_new = get_ssh_connections()

        # Remove old connections
        # Create list of keys to remove to avoid runtime error during iteration
        keys_to_remove = []
        for k, c in ssh_conns.items():
            if k not in ssh_conns_new:
                keys_to_remove.append(k)
            else:
                # Reset counters for existing connections
                c.latest_bytes = 0
                c.small_pkt_count = 0
                c.large_pkt_count = 0
        
        for k in keys_to_remove:
            del ssh_conns[k]

        # Add new connections
        for k, c in ssh_conns_new.items():
            if k not in ssh_conns:
                # Initialize counters
                c.latest_bytes = 0
                c.small_pkt_count = 0
                c.large_pkt_count = 0
                ssh_conns[k] = c

        sniff(timeout=config.SNIFF_TIMEOUT, prn=process_packet)

        time.sleep(1)

        print("-" * 30)
        print(f"{len(ssh_conns)} connections")
        
        # Iterate over a copy of values
        for c in list(ssh_conns.values()):
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
                
                if c in ssh_conns.values():
                    # Find key to remove
                    key_to_remove = None
                    for k, v in ssh_conns.items():
                        if v == c:
                            key_to_remove = k
                            break
                    if key_to_remove:
                        del ssh_conns[key_to_remove]
                continue

            if score >= 100:
                if c not in ssh_attacks:
                    ssh_attacks.append(c)

        # Memory Limit Enforcement
        if len(ssh_attacks) > config.MAX_LOG_ENTRIES:
            ssh_attacks = ssh_attacks[-config.MAX_LOG_ENTRIES:]
            
        if len(ssh_banned) > config.MAX_LOG_ENTRIES:
            ssh_banned = ssh_banned[-config.MAX_LOG_ENTRIES:]

        save_attack_log(ssh_attacks)


if __name__ == "__main__":

    config = Config.load()

    ssh_attacks = load_attack_log()
    ssh_banned = []
    # ssh_conns needs to be a dict now. 
    # We can't easily restore state from ssh_attacks list to dict without re-scanning, 
    # so we start empty or convert if needed. 
    # For simplicity, let's start fresh for active connections or just rely on get_ssh_connections()
    ssh_conns: Dict[Tuple[str, int, str, int], Connections] = {}

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
