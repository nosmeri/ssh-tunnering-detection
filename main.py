from dataclasses import dataclass, field
import psutil
from scapy.all import *
import time
import json

#상수들
port_score = 50 #비표준 포트 점수
ssh_con_score = 20 #ssh 연결 방법 점수
min_time = 100
time_score = 10 #1분마다 점수 비례(기준은 나중에 바꿀 수 있음)
data_score = 1 #100MB마다 점수 비례
sniff_timeout = 3 #sniff 주기

@dataclass()
class Connections:
    laddr: str
    lport: int
    raddr: str
    rport: int
    pid: int
    cmdline: str
    ts: float = field(default=time.time(), compare=False)
    bytes: int = field(default=0, compare=False)
    latest_bytes: int = field(default=0, compare=False)


def get_ssh_connections():
    ssh_conns=[]
    conns = psutil.net_connections(kind="tcp")
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED:
            if c.pid==None:
                continue
            try:
                process = psutil.Process(c.pid)
            except psutil.NoSuchProcess:
                continue
            process_name = process.name()
            if "ssh" not in process_name.lower():
                continue
            ssh_conns.append(
                Connections(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.pid, process.cmdline())
            )
    return ssh_conns

def cal_score(conn):
    score = 0
    if conn.lport !=22 and conn.rport !=22:
        score += port_score #비표준 포트 점수
    if time.time()-conn.ts > min_time:
        score += (time.time()-conn.ts)//60 * time_score
        score += (conn.latest_bytes//(1024*1024)) * data_score 
    if conn.cmdline and "-R" in conn.cmdline or "-D" in conn.cmdline or "-L" in conn.cmdline:
        score += ssh_con_score
    return score

def process_packet(packet):
    if packet.haslayer(TCP):
        for c in ssh_conns:
            if (packet[TCP].sport == c.lport and packet[TCP].dport == c.rport) or (packet[TCP].dport == c.lport and packet[TCP].sport == c.rport):
                c.bytes += len(packet)
                c.latest_bytes += len(packet)
                #print(f"Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}, Size: {len(packet)}")
                break

if __name__ == "__main__":
    ssh_conns=[]


    while True:
        ssh_conns_new = get_ssh_connections()


        for c in ssh_conns:
            if c not in ssh_conns_new:
                ssh_conns.remove(c)
        
        for c in ssh_conns_new:
            if c not in ssh_conns:
                ssh_conns.append(c)
        
        for c in ssh_conns:
            c.latest_bytes = 0

        sniff(timeout=sniff_timeout, prn=process_packet)

        time.sleep(1)


        for c in ssh_conns:
            score=cal_score(c)
            print(score)
            if score >=100:
                print("Warning!!!!!")
        
        print(ssh_conns)

# 포트, 연결 지속, 데이터 량, -R -D -L
