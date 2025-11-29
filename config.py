import json
from dataclasses import asdict, dataclass
from pathlib import Path

CFG_PATH = Path("config.json")


@dataclass
class Config:
    """
    SSH 터널링 탐지기 설정 클래스입니다.

    Attributes:
        PORT_SCORE (float): 비표준 포트(22번 아님) 사용 시 부여되는 점수.
        SSH_CON_SCORE (float): SSH 터널링 옵션(-R, -D, -L) 사용 시 부여되는 점수.
        MIN_TIME (float): 시간 점수 계산을 위한 최소 연결 지속 시간(초).
        TIME_SCORE (float): 연결 지속 시간에 비례하여 부여되는 점수 (분당).
        DATA_SCORE (float): 데이터 전송량에 비례하여 부여되는 점수 (10초/1MB 기준).
        INTERACTIVE_SCORE (float): 작은 패킷 빈도가 높을 때 부여되는 점수 (Interactive Shell).
        BULK_SCORE (float): 큰 패킷 빈도가 높을 때 부여되는 점수 (Bulk Transfer).
        SNIFF_TIMEOUT (float): 패킷 스니핑 주기(초).
        MITIGATION_ENABLED (bool): 자동 차단 기능 활성화 여부.
        CRITICAL_SCORE (float): 자동 차단이 트리거되는 점수 임계값.
        MAX_LOG_ENTRIES (int): 메모리에 유지할 최대 로그 개수.
        SOCK_PATH (str): Unix 도메인 소켓 경로.
        TOKEN_FILE (str): 인증 토큰 파일 경로 (권한 0600).
        WHITELIST_FILE (str): 화이트리스트 파일 경로.
        ATTACK_LOG_FILE (str): 공격 로그 파일 경로.
        INTERFACE_TIME_INTERVAL_MINUTE (int): 웹 인터페이스 그래프의 시간 간격(분).
        INTERFACE_DATA_COUNT (int): 웹 인터페이스 그래프에 표시할 데이터 포인트 개수.
    """
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
        """
        설정 파일을 로드합니다. 파일이 없으면 기본 설정으로 생성합니다.

        Args:
            path (Path): 설정 파일 경로. 기본값은 CFG_PATH.

        Returns:
            Config: 로드된 설정 객체.
        """
        if not path.exists():
            path.write_text(json.dumps(asdict(cls()), indent=2, ensure_ascii=False))
            ret_cls = cls()
        else:
            ret_cls = cls(**json.loads(path.read_text()))

        path.write_text(json.dumps(asdict(ret_cls), indent=2, ensure_ascii=False))
        return ret_cls
