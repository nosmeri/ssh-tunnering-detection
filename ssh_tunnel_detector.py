

from __future__ import annotations
import argparse
import dataclasses
import json
import psutil
import re
import socket
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

# scapy는 선택 사항(스니핑/pcap 분석에만 사용)
try:
    from scapy.all import sniff, rdpcap, TCP, Raw

    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


SSH_BIN_NAMES = {"ssh", "autossh"}
SSH_DEFAULT_PORTS = {22}
COMMON_SSH_MASQUERADE_PORTS = {
    443,
    80,
    53,
}  # 흔히 위장에 쓰이는 포트 (관측 기반 휴리스틱)
LOCALHOSTS = {"127.0.0.1", "::1"}


@dataclasses.dataclass
class Alert:
    time: float
    kind: str  # PROCESS|SOCKET|PCAP
    severity: str  # info|low|med|high
    message: str
    detail: dict

    def to_dict(self):
        d = dataclasses.asdict(self)
        d["time_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.time))
        return d


class TunnelDetector:
    def __init__(
        self,
        allow_hosts: Set[str] | None = None,
        allow_local_ports: Set[int] | None = None,
    ):
        self.allow_hosts = {h.strip().lower() for h in (allow_hosts or set())}
        self.allow_local_ports = set(allow_local_ports or set())
        self.alerts: List[Alert] = []

    # --------------------------- 프로세스/소켓 기반 ---------------------------
    def _iter_ssh_procs(self) -> List[psutil.Process]:
        procs = []
        for p in psutil.process_iter(attrs=["name", "exe", "cmdline"]):
            try:
                name = (p.info.get("name") or "").lower()
                exe = (p.info.get("exe") or "").lower()
                if any(b in name for b in SSH_BIN_NAMES) or any(
                    b in exe for b in SSH_BIN_NAMES
                ):
                    procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs

    _RE_FLAG = re.compile(r"\s-(?P<flag>[LRD])\s*(?P<arg>[^-].*?)?(?=\s-\w|$)")
    _RE_CFG = re.compile(r"(?i)\b(LocalForward|RemoteForward|DynamicForward)\b")

    def _parse_cmdline_for_forwards(self, cmdline: List[str]) -> Dict[str, List[str]]:
        text = " ".join(cmdline)
        found: Dict[str, List[str]] = {"L": [], "R": [], "D": []}
        # 단축 플래그(-L/-R/-D) 추출
        for m in self._RE_FLAG.finditer(" " + text + " "):
            flag = m.group("flag")
            arg = (m.group("arg") or "").strip()
            if flag in found:
                if arg:
                    found[flag].append(arg)
                else:
                    found[flag].append("")
        # 설정 파일 기반 지시어 추정(정확히 어떤 포워딩인지는 모름)
        if self._RE_CFG.search(text):
            found.setdefault("CFG", []).append("Forward directive present")
        return found

    def _connections_by_pid(
        self, pid: int
    ) -> Tuple[List[psutil._common.sconn], List[psutil._common.sconn]]:
        """return (listening, established) for a pid"""
        listens = []
        estabs = []
        try:
            cons = psutil.Process(pid).connections(kind="tcp")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return listens, estabs
        for c in cons:
            if c.status == psutil.CONN_LISTEN:
                listens.append(c)
            elif c.status == psutil.CONN_ESTABLISHED:
                estabs.append(c)
        return listens, estabs

    def scan_processes_and_sockets(self, verbose=False):
        for p in self._iter_ssh_procs():
            try:
                cmdline = p.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            forwards = self._parse_cmdline_for_forwards(cmdline)
            listens, estabs = self._connections_by_pid(p.pid)

            # 휴리스틱 1) -D or localhost LISTEN => 동적/로컬 포워딩 정황
            localhost_listen = [
                c for c in listens if c.laddr and (c.laddr.ip in LOCALHOSTS)
            ]
            if forwards.get("D") or localhost_listen:
                sev = "med"
                if forwards.get("D") and localhost_listen:
                    sev = "high"
                self._alert(
                    kind="PROCESS",
                    severity=sev,
                    message="Dynamic/Local forward suspected (-D or localhost listening by ssh)",
                    detail={
                        "pid": p.pid,
                        "cmdline": cmdline,
                        "listen": [self._fmt_conn(c) for c in localhost_listen],
                        "established": [self._fmt_conn(c) for c in estabs],
                    },
                )

            # 휴리스틱 2) 동일 PID에서 localhost LISTEN + 외부로 ESTABLISHED(22/443 등)
            if localhost_listen and estabs:
                out = [
                    c
                    for c in estabs
                    if self._is_remote(c)
                    and (
                        c.raddr.port
                        in (SSH_DEFAULT_PORTS | COMMON_SSH_MASQUERADE_PORTS)
                    )
                ]
                if out:
                    self._alert(
                        kind="SOCKET",
                        severity="high",
                        message="SSH process has localhost LISTEN and external ESTABLISHED to SSH-like port",
                        detail={
                            "pid": p.pid,
                            "cmdline": cmdline,
                            "listen": [self._fmt_conn(c) for c in localhost_listen],
                            "external": [self._fmt_conn(c) for c in out],
                        },
                    )

            # 휴리스틱 3) -R 존재 => 리버스 포워딩 정황
            if forwards.get("R"):
                self._alert(
                    kind="PROCESS",
                    severity="med",
                    message="Remote (-R) port forwarding detected in ssh cmdline",
                    detail={"pid": p.pid, "cmdline": cmdline, "R_args": forwards["R"]},
                )

            # 화이트리스트 제외(호스트/포트)
            self._apply_allowlist(p, listens, estabs)

            if verbose:
                print(f"[DBG] pid={p.pid} cmd={' '.join(cmdline)}")
                for c in listens + estabs:
                    print("      ", self._fmt_conn(c))

    def _apply_allowlist(self, p: psutil.Process, listens, estabs):
        if not (self.allow_hosts or self.allow_local_ports):
            return
        # 호스트 허용: 외부 연결 목적지 호스트/IP가 허용 목록이면 경보 낮춤
        if self.allow_hosts:
            for a in self.alerts:
                if a.detail.get("pid") != p.pid:
                    continue
                lowered = False
                for c in a.detail.get("external", []):
                    host = c.get("raddr_ip", "").lower()
                    if host in self.allow_hosts:
                        a.severity = "info"
                        a.message += " (allowed host matched)"
                        lowered = True
                if lowered:
                    continue
        # 로컬 포트 허용: 예) 사내 표준 프록시 포트 등
        if self.allow_local_ports:
            for a in self.alerts:
                if a.detail.get("pid") != p.pid:
                    continue
                for c in a.detail.get("listen", []):
                    port = c.get("laddr_port")
                    if port in self.allow_local_ports:
                        a.severity = "info"
                        a.message += " (allowed local port matched)"

    @staticmethod
    def _is_remote(c: psutil._common.sconn) -> bool:
        try:
            if not c.raddr:
                return False
            rip = c.raddr.ip
            return not (
                rip.startswith("10.")
                or rip.startswith("172.")
                or rip.startswith("192.168.")
                or rip == "127.0.0.1"
            )
        except Exception:
            return False

    @staticmethod
    def _fmt_conn(c: psutil._common.sconn) -> dict:
        d = {
            "status": c.status,
            "family": str(c.family),
            "type": str(c.type),
            "pid": c.pid,
            "laddr_ip": getattr(c.laddr, "ip", None) if c.laddr else None,
            "laddr_port": getattr(c.laddr, "port", None) if c.laddr else None,
            "raddr_ip": getattr(c.raddr, "ip", None) if c.raddr else None,
            "raddr_port": getattr(c.raddr, "port", None) if c.raddr else None,
        }
        return d

    def _alert(self, kind: str, severity: str, message: str, detail: dict):
        self.alerts.append(
            Alert(
                time=time.time(),
                kind=kind,
                severity=severity,
                message=message,
                detail=detail,
            )
        )

    # --------------------------- 패킷 기반(라이브/pcap) ---------------------------
    def _packet_handler(self, pkt):
        try:
            if not pkt.haslayer(TCP):
                return
            tcp = pkt.getlayer(TCP)
            sport, dport = int(tcp.sport), int(tcp.dport)

            if pkt.haslayer(Raw):
                data: bytes = pkt[Raw].load
            else:
                data = b""

            # 비표준 포트에서 SSH 매직 문자열 \"SSH-\"가 보이면 터널링(위장) 의심
            if data.startswith(b"SSH-") and dport not in SSH_DEFAULT_PORTS:
                sip = pkt[0][1].src if hasattr(pkt[0][1], "src") else "?"
                dip = pkt[0][1].dst if hasattr(pkt[0][1], "dst") else "?"
                sev = "high" if dport in COMMON_SSH_MASQUERADE_PORTS else "med"
                self._alert(
                    kind="PCAP",
                    severity=sev,
                    message="Non-standard port carrying SSH handshake detected",
                    detail={
                        "src": sip,
                        "dst": dip,
                        "dport": dport,
                        "first_bytes": data[:16].decode(errors="ignore"),
                    },
                )
        except Exception:
            return

    def sniff_live(self, iface: str, seconds: int = 60, bpf: Optional[str] = None):
        if not SCAPY_OK:
            print(
                "[!] scapy가 설치되지 않아 스니핑을 사용할 수 없습니다. 'pip install scapy' 후 다시 시도하세요."
            )
            return
        flt = bpf or "tcp"
        print(f"[*] sniff iface={iface} seconds={seconds} filter={flt}")
        sniff(
            iface=iface,
            filter=flt,
            prn=self._packet_handler,
            timeout=seconds,
            store=False,
        )

    def analyze_pcap(self, pcap_path: str):
        if not SCAPY_OK:
            print(
                "[!] scapy가 설치되지 않아 PCAP 분석을 사용할 수 없습니다. 'pip install scapy' 후 다시 시도하세요."
            )
            return
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            self._packet_handler(pkt)

    # --------------------------- 결과 출력 ---------------------------
    def print_report(self, as_json: bool = False):
        if as_json:
            for a in self.alerts:
                print(json.dumps(a.to_dict(), ensure_ascii=False))
            return
        if not self.alerts:
            print("탐지된 의심 정황 없음.")
            return
        print("== SSH 터널 의심 알림 ==")
        for a in self.alerts:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.time))
            print(f"[{ts}] ({a.kind}|{a.severity}) {a.message}")
            print(json.dumps(a.detail, ensure_ascii=False, indent=2))
            print("-")


def build_argparser():
    p = argparse.ArgumentParser(description="SSH 터널링 탐지 도구")
    sub = p.add_subparsers(dest="mode", required=True)

    p.add_argument("--json", action="store_true", help="결과를 JSON 라인으로 출력")
    p.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="허용(화이트리스트) 원격 호스트/IP. 여러 번 지정 가능",
    )
    p.add_argument(
        "--allow-local-port",
        type=int,
        action="append",
        default=[],
        help="허용 로컬 리슨 포트. 여러 번 지정 가능",
    )

    sp_scan = sub.add_parser("scan", help="프로세스/소켓 기반 점검")
    sp_scan.add_argument(
        "--interval", type=int, default=0, help="주기적 스캔 간격(초). 0이면 1회 스캔"
    )
    sp_scan.add_argument("--verbose", action="store_true", help="디버그 출력")

    sp_sniff = sub.add_parser("sniff", help="라이브 트래픽 스니핑")
    sp_sniff.add_argument(
        "-i", "--iface", required=True, help="수집 인터페이스명 (예: eth0)"
    )
    sp_sniff.add_argument("--seconds", type=int, default=60, help="수집 시간(초)")
    sp_sniff.add_argument("--bpf", default="tcp", help="BPF 필터 (예: tcp port not 22)")

    sp_pcap = sub.add_parser("pcap", help="PCAP 파일 분석")
    sp_pcap.add_argument("pcap", help="분석할 PCAP 파일 경로")

    return p


def main(argv: List[str]):
    args = build_argparser().parse_args(argv)
    det = TunnelDetector(
        allow_hosts=set(args.allow_host), allow_local_ports=set(args.allow_local_port)
    )

    if args.mode == "scan":

        def once():
            det.scan_processes_and_sockets(verbose=getattr(args, "verbose", False))
            det.print_report(as_json=args.json)

        if args.interval and args.interval > 0:
            while True:
                det.alerts.clear()
                once()
                time.sleep(args.interval)
        else:
            once()

    elif args.mode == "sniff":
        if not SCAPY_OK:
            print("[!] scapy 필요: pip install scapy")
            sys.exit(1)
        det.sniff_live(iface=args.iface, seconds=args.seconds, bpf=args.bpf)
        det.print_report(as_json=args.json)

    elif args.mode == "pcap":
        if not SCAPY_OK:
            print("[!] scapy 필요: pip install scapy")
            sys.exit(1)
        det.analyze_pcap(args.pcap)
        det.print_report(as_json=args.json)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        pass
