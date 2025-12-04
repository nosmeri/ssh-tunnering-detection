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


def get_ssh_connections() -> Dict[Tuple[str, int, str, int], Connections]:
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
    score = 0

    if conn.lport != 22 and conn.rport != 22:
        score += config.PORT_SCORE

    duration = time.time() - conn.ts
    if duration > config.MIN_TIME:
        score += ((duration / 60) ** 1.5) * config.TIME_SCORE

    if conn.cmdline and (
        "-R" in conn.cmdline
    ):
        score += config.SSH_CON_SCORE

    score += (
        (conn.latest_bytes // (1024 * 1024))
        * duration
        // 60
        * config.DATA_SCORE
    )

    if conn.small_pkt_count > 20:
        score += config.INTERACTIVE_SCORE * (conn.small_pkt_count / 10)
    
    if conn.large_pkt_count > 5:
        score += config.BULK_SCORE * (conn.large_pkt_count / 5)

    return score


def process_packet(packet):
    if packet.haslayer(TCP):
        pkt_len = len(packet)
        
        src_ip = packet[TCP].options[0][1] if False else packet[0][1].src
        if not packet.haslayer("IP"):
            return

        src = packet["IP"].src
        dst = packet["IP"].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        c = ssh_conns.get((src, sport, dst, dport))
        
        if not c:
            c = ssh_conns.get((dst, dport, src, sport))
            
        if c:
            c.bytes += pkt_len
            c.latest_bytes += pkt_len
            
            if pkt_len < 100:
                c.small_pkt_count += 1
            elif pkt_len > 1000:
                c.large_pkt_count += 1


def load_token():
    with open(config.TOKEN_FILE, "r") as f:
        return f.read().strip()


def prepare_socket():
    if os.path.exists(config.SOCK_PATH):
        os.remove(config.SOCK_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(config.SOCK_PATH)
    os.chmod(config.SOCK_PATH, 0o660)
    os.chown(config.SOCK_PATH, 1000, 1000)
    srv.listen(8)
    return srv


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


def compute_hmac_for(obj: Dict[str, Any]) -> str:
    check = {"type": obj["type"], "payload": obj["payload"]}
    cb = json.dumps(check, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(SECRET_TOKEN, cb, hashlib.sha256).hexdigest()


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
        
        Config.load().MITIGATION_ENABLED = config.MITIGATION_ENABLED
        Config.load().CRITICAL_SCORE = config.CRITICAL_SCORE
        
        current_cfg = Config.load()
        current_cfg.MITIGATION_ENABLED = config.MITIGATION_ENABLED
        current_cfg.CRITICAL_SCORE = config.CRITICAL_SCORE
        
        with open(config.CFG_PATH if hasattr(config, 'CFG_PATH') else "config.json", "w") as f:
            json.dump(asdict(current_cfg), f, indent=2, ensure_ascii=False)

        return {"ok": True, "result": "updated"}

    return {"ok": False, "error": "unknown type"}


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


def ssh_detector():
    global ssh_conns, ssh_attacks, ssh_banned
    while True:
        ssh_conns_new = get_ssh_connections()

        keys_to_remove = []
        for k, c in ssh_conns.items():
            if k not in ssh_conns_new:
                keys_to_remove.append(k)
            else:
                c.latest_bytes = 0
                c.small_pkt_count = 0
                c.large_pkt_count = 0
        
        for k in keys_to_remove:
            del ssh_conns[k]

        for k, c in ssh_conns_new.items():
            if k not in ssh_conns:
                c.latest_bytes = 0
                c.small_pkt_count = 0
                c.large_pkt_count = 0
                ssh_conns[k] = c

        sniff(timeout=config.SNIFF_TIMEOUT, prn=process_packet)

        time.sleep(1)

        print("-" * 30)
        print(f"{len(ssh_conns)} connections")
        
        for c in list(ssh_conns.values()):
            score = cal_score(c)
            print(c)
            print(score)

            if score >= 100:
                if c not in ssh_attacks:
                    ssh_attacks.append(c)
            
            if score >= config.CRITICAL_SCORE and config.MITIGATION_ENABLED:
                print(f"CRITICAL SCORE DETECTED: {score} for PID {c.pid}. Mitigating...")
                kill_process(c.pid)
                
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

        if len(ssh_attacks) > config.MAX_LOG_ENTRIES:
            ssh_attacks = ssh_attacks[-config.MAX_LOG_ENTRIES:]
            
        if len(ssh_banned) > config.MAX_LOG_ENTRIES:
            ssh_banned = ssh_banned[-config.MAX_LOG_ENTRIES:]

        save_attack_log(ssh_attacks)


if __name__ == "__main__":

    config = Config.load()

    ssh_attacks = load_attack_log()
    ssh_banned = []
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



