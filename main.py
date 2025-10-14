from dataclasses import dataclass, field
import psutil
from scapy.all import *
import time
import json


@dataclass()
class Connections:
    laddr: str
    lport: int
    raddr: str
    rport: int
    pid: int
    cmdline: str
    ts: float = field(default=time.time(), compare=False)


def get_ssh_connections():
    ssh_conns=[]
    conns = psutil.net_connections(kind="tcp")
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED:
            if c.pid==None:
                continue
            process = psutil.Process(c.pid)
            process_name = process.name()
            if "ssh" not in process_name.lower():
                continue
            ssh_conns.append(
                Connections(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.pid, process.cmdline())
            )
    return ssh_conns


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
        
        time.sleep(1)

        print(ssh_conns)

    #ports = list(map(lambda x: f"tcp.port=={x[0][1]}", ssh_conns))
    #sniff(filter=" || ".join(ports))

# 포트, 연결 지속, 데이터 량, -R -D -L
