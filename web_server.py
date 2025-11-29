import hashlib
import hmac
import json
import socket
import struct
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional

from fastapi import FastAPI, Query, Request
from fastapi.templating import Jinja2Templates

from config import Config


class RequestType(Enum):
    """
    탐지기 서버에 요청할 수 있는 작업 유형을 정의하는 열거형입니다.
    """
    ADD_WHITELIST = "whitelist_add"
    REMOVE_WHITELIST = "whitelist_remove"
    LIST_WHITELIST = "list_whitelist"
    GET_LOG = "get_log"
    GET_BANNED = "get_banned"
    GET_STATS = "get_stats"
    GET_CONFIG = "get_config"
    SET_CONFIG = "set_config"


config = Config.load()


def load_token():
    """
    인증 토큰을 파일에서 로드합니다.

    Returns:
        bytes: 로드된 토큰 바이트.
    """
    with open(config.TOKEN_FILE, "r") as f:
        return f.read().strip().encode()


SECRET = load_token()


def compute_hmac(type_, payload):
    """
    요청에 대한 HMAC 서명을 계산합니다.

    Args:
        type_ (str): 요청 유형.
        payload (dict): 요청 페이로드.

    Returns:
        str: 계산된 HMAC 16진수 문자열.
    """
    obj = {"type": type_, "payload": payload}
    b = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(SECRET, b, hashlib.sha256).hexdigest()


def send_request(obj):
    """
    탐지기 서버(Unix 소켓)로 요청을 전송하고 응답을 받습니다.

    Args:
        obj (dict): 전송할 요청 객체.

    Returns:
        dict: 서버로부터 받은 응답 객체.
    """
    data = json.dumps(obj, ensure_ascii=False).encode()
    hdr = struct.pack(">I", len(data))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(config.SOCK_PATH)
    except (FileNotFoundError, ConnectionRefusedError):
        return {"ok": False, "error": "Detector is not running (socket not found)"}
    
    try:
        s.sendall(hdr + data)
        # recv response
        hdr = s.recv(4)
        if not hdr or len(hdr) < 4:
            return {"ok": False, "error": "Connection closed unexpectedly"}
        length = struct.unpack(">I", hdr)[0]
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode())
    finally:
        s.close()


def generic_api_request(type_: RequestType, payload: Dict = {}):
    """
    일반적인 API 요청을 생성하고 전송합니다.

    Args:
        type_ (RequestType): 요청 유형.
        payload (Dict): 요청 페이로드.

    Returns:
        dict: 서버 응답.
    """
    req = {
        "type": type_.value,
        "payload": payload,
        "hmac": compute_hmac(type_.value, payload),
    }
    return send_request(req)


app = FastAPI()


templates = Jinja2Templates(directory="./templates")


@app.get("/")
def main_page(request: Request):
    """
    메인 대시보드 페이지를 렌더링합니다.
    """
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/get_logs")
def get_data(interval: int = Query(None, gt=0)):
    """
    공격 로그 통계 데이터를 조회합니다.

    Args:
        interval (int, optional): 그래프 시간 간격(분).

    Returns:
        dict: 그래프 라벨과 데이터 리스트.
    """
    now = datetime.now()
    resp = generic_api_request(RequestType.GET_LOG)
    if not resp or not resp.get("ok"):
        return {"labels": [], "datas": []}
        
    attacks_ts = list(
        map(lambda x: x["ts"], resp["result"])
    )

    # Use provided interval or default from config
    time_interval = interval if interval else config.INTERFACE_TIME_INTERVAL_MINUTE

    labels = []
    datas = []
    for i in range(config.INTERFACE_DATA_COUNT, -1, -1):
        t1 = now - timedelta(minutes=time_interval * (i + 1))
        t2 = now - timedelta(minutes=time_interval * i)
        cnt = 0
        for at in attacks_ts:
            if t1.timestamp() <= at < t2.timestamp():
                cnt += 1
        labels.append(f"{t1.strftime('%H:%M:%S')} ~ {t2.strftime('%H:%M:%S')}")
        datas.append(cnt)
    return {"labels": labels, "datas": datas}


@app.get("/api/get_attacks")
def get_attacks(limit: int = Query(100, gt=0, le=2000), query: Optional[str] = None):
    """
    최근 공격 로그 목록을 조회합니다.

    Args:
        limit (int): 조회할 최대 로그 개수.
        query (str, optional): 필터링할 검색어.

    Returns:
        list: 공격 로그 객체 리스트.
    """
    resp = generic_api_request(RequestType.GET_LOG)
    if not resp or not resp.get("ok"):
        return []

    attacks = resp["result"][-limit:]
    if query:
        filtered = []
        for x in attacks:
            if query in str(x["laddr"]) or query in str(x["raddr"]) or query in str(x["lport"]) or query in str(x["rport"]):
                filtered.append(x)
        return filtered
    return attacks


@app.get("/api/get_banned")
def get_banned():
    """
    차단된 공격 로그 목록을 조회합니다.

    Returns:
        list: 차단된 공격 로그 객체 리스트.
    """
    resp = generic_api_request(RequestType.GET_BANNED)
    if not resp or not resp.get("ok"):
        return []
    return resp["result"]


@app.get("/api/get_whitelist")
def get_whitelist():
    """
    화이트리스트 목록을 조회합니다.

    Returns:
        dict: 화이트리스트 목록을 포함한 응답.
    """
    return generic_api_request(RequestType.LIST_WHITELIST)


@app.post("/api/add_whitelist")
def add_whitelist(ip: str = Query(...)):
    """
    화이트리스트에 IP를 추가합니다.

    Args:
        ip (str): 추가할 IP 주소.

    Returns:
        dict: 처리 결과.
    """
    return generic_api_request(RequestType.ADD_WHITELIST, {"ip": ip})


@app.post("/api/remove_whitelist")
def remove_whitelist(ip: str = Query(...)):
    """
    화이트리스트에서 IP를 제거합니다.

    Args:
        ip (str): 제거할 IP 주소.

    Returns:
        dict: 처리 결과.
    """
    return generic_api_request(RequestType.REMOVE_WHITELIST, {"ip": ip})


@app.get("/api/get_config")
def get_config():
    """
    현재 설정을 조회합니다.

    Returns:
        dict: 설정 정보를 포함한 응답.
    """
    return generic_api_request(RequestType.GET_CONFIG)


@app.post("/api/set_config")
def set_config(mitigation_enabled: bool = Query(None)):
    """
    설정을 변경합니다.

    Args:
        mitigation_enabled (bool, optional): 자동 차단 활성화 여부.

    Returns:
        dict: 처리 결과.
    """
    payload = {}
    if mitigation_enabled is not None:
        payload["mitigation_enabled"] = mitigation_enabled
    return generic_api_request(RequestType.SET_CONFIG, payload)
