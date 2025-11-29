import json
from dataclasses import asdict, dataclass
from pathlib import Path

CFG_PATH = Path("config.json")


@dataclass
class Config:
    PORT_SCORE: float = 30  # 비표준 포트 점수(not 22)
    SSH_CON_SCORE: float = 20  # ssh 연결 방법 점수(-R, -D, -L)
    MIN_TIME: float = 100  # 시간 점수 최소 시간(초)
    TIME_SCORE: float = 1  # 1분마다 점수 비례(기준은 나중에 바꿀 수 있음)
    DATA_SCORE: float = 10  # 최근 10초 1MB마다 점수 비례
    INTERACTIVE_SCORE: float = 5  # 작은 패킷 빈도 점수
    BULK_SCORE: float = 15  # 큰 패킷 빈도 점수
    SNIFF_TIMEOUT: float = 3  # sniff 주기

    MITIGATION_ENABLED: bool = False  # 자동 차단 활성화 여부
    CRITICAL_SCORE: float = 1000  # 자동 차단 점수 임계값
    MAX_LOG_ENTRIES: int = 1000  # 메모리 내 로그 최대 개수

    SOCK_PATH: str = "./ssh_detector.sock"
    TOKEN_FILE: str = "./token"  # 권한 0600
    WHITELIST_FILE: str = "./whitelist.json"
    ATTACK_LOG_FILE: str = "./ssh_detector_attacks.log"

    INTERFACE_TIME_INTERVAL_MINUTE: int = 10
    INTERFACE_DATA_COUNT: int = 30

    @classmethod
    def load(cls, path: Path = CFG_PATH):
        if not path.exists():
            path.write_text(json.dumps(asdict(cls()), indent=2, ensure_ascii=False))
            ret_cls = cls()
        else:
            ret_cls = cls(**json.loads(path.read_text()))

        path.write_text(json.dumps(asdict(ret_cls), indent=2, ensure_ascii=False))
        return ret_cls
