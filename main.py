import psutil, time, threading, collections, datetime, os, signal
from scapy.all import sniff, TCP, IP

# ────────────────────  ★ 설정  ★  ────────────────────
CHECK_INTERVAL        = 10      # 초 – psutil 순회 주기
WATCH_DURATION        = 300     # 초 – SSH 세션 누적 시간 임계
KEEPALIVE_THRESHOLD   = 12      # 최근 60s 내 tcp.len==0 개수
ALLOWED_IPS           = {"203.0.113.10"}   # 사내·Git 등 업무용 SSH 허용 목록
KILL_SUSPICIOUS_PROC  = False   # True 설정 시 프로세스 강제 종료
LOG_FILE              = "./reverse_ssh_detect.log"
# ─────────────────────────────────────────────────────

# 최근 keep-alive 빈 패킷 타임스탬프 저장
ka_history = collections.defaultdict(list)

def log(msg):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line  = f"[{stamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def pkt_callback(pkt):
    """scapy sniff 콜백 – tcp.len==0 keep-alive 패턴 기록"""
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        tcp = pkt[TCP]; ip = pkt[IP]
        if tcp.dport == 22 or tcp.sport == 22:
            if len(tcp.payload) == 0:           # 빈 패킷만 기록
                key = (ip.src, ip.dst)
                ka_history[key].append(time.time())

def start_sniffer():
    sniff(filter="tcp port 22", prn=pkt_callback, store=0)

def score_connection(conn, cmdline, now):
    """각 소켓에 대해 의심 점수 계산"""
    score = 0
    r_ip   = conn.raddr.ip if conn.raddr else None

    # 1) -R / -D 플래그가 있으면  +40
    if "-R" in cmdline or "-D" in cmdline:
        score += 40

    # 2) 허용 IP가 아니면            +15
    if r_ip and r_ip not in ALLOWED_IPS:
        score += 15

    # 3) 세션 지속 시간 ≥ WATCH_DURATION  +25
    dur = now - conn.create_time if hasattr(conn, "create_time") else 0
    if dur >= WATCH_DURATION:
        score += 25

    # 4) 최근 60초  keep-alive 빈 패킷 수   +20
    key_fwd = (conn.laddr.ip, r_ip)
    key_rev = (r_ip, conn.laddr.ip)
    for key in (key_fwd, key_rev):
        recent = [t for t in ka_history[key] if now - t < 60]
        if len(recent) >= KEEPALIVE_THRESHOLD:
            score += 20
            break
    return score

def monitor_loop():
    log("=== Reverse-SSH 탐지 루프 시작 ===")
    while True:
        now = time.time()
        for p in psutil.process_iter(['pid','name','cmdline']):
            if p.info["name"] != "ssh": continue
            cmdline = " ".join(p.info["cmdline"])

            # 해당 PID가 가진 소켓만 조회
            try:
                conns = p.net_connections(kind="tcp")
            except psutil.AccessDenied:
                continue

            for c in conns:
                if c.status != psutil.CONN_ESTABLISHED: continue
                if not (c.raddr and c.raddr.port == 22): continue  # SSH outbound

                score = score_connection(c, cmdline, now)
                if score >= 60:
                    log(f"⚠️  Suspicious SSH tunnel  | score={score}"
                        f" | PID={p.pid} | {c.laddr.ip}:{c.laddr.port} ➜ {c.raddr.ip}:22"
                        f" | cmd='{cmdline}'")
                    if KILL_SUSPICIOUS_PROC:
                        try:
                            p.send_signal(signal.SIGTERM)
                            log(f"  ↳ 프로세스 종료 시도 완료.")
                        except Exception as e:
                            log(f"  ↳ 종료 실패: {e}")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    # 패킷 스니퍼를 별도 쓰레드로
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    try:
        monitor_loop()
    except KeyboardInterrupt:
        log("탐지 루프 종료.")

