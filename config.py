from dataclasses import dataclass, asdict
import json
from pathlib import Path

CFG_PATH = Path("config.json")


@dataclass
class Config:
    PORT_SCORE: float = 30 #비표준 포트 점수
    SSH_CON_SCORE: float = 20 #ssh 연결 방법 점수
    MIN_TIME: float = 100
    TIME_SCORE: float = 1 #1분마다 점수 비례(기준은 나중에 바꿀 수 있음)
    DATA_SCORE: float = 10 #1MB마다 점수 비례
    SNIFF_TIMEOUT: float = 3 #sniff 주기

    def save(self, path: Path = CFG_PATH) -> None:
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls, path: Path = CFG_PATH):
        if not path.exists():
            return cls()
        return cls(**json.loads(path.read_text()))
