from dataclasses import dataclass, asdict
import json
from pathlib import Path

CFG_PATH = Path("config.json")


@dataclass
class Config:
    PORT_SCORE: float = 30 # 비표준 포트 점수(not 22)
    SSH_CON_SCORE: float = 20 # ssh 연결 방법 점수(-R, -D, -L)
    MIN_TIME: float = 100 # 시간 점수 최소 시간(초)
    TIME_SCORE: float = 1 # 1분마다 점수 비례(기준은 나중에 바꿀 수 있음)
    DATA_SCORE: float = 10 # 최근 10초 1MB마다 점수 비례
    SNIFF_TIMEOUT: float = 3 # sniff 주기

    SOCK_PATH: str = "./ssh_detector.sock"
    TOKEN_FILE: str = "./token"     # 권한 0600
    WHITELIST_FILE: str = "./whitelist.json"
    ATTACK_LOG_FILE: str = "./ssh_detector_attacks.log"

    @classmethod
    def load(cls, path: Path = CFG_PATH):
        if not path.exists():
            path.write_text(json.dumps(asdict(cls()), indent=2, ensure_ascii=False))
            ret_cls = cls()
        else:
            ret_cls= cls(**json.loads(path.read_text()))

        path.write_text(json.dumps(asdict(ret_cls), indent=2, ensure_ascii=False))
        return ret_cls
