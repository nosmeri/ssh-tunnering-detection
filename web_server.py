import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime, timedelta
from enum import Enum
from re import I
from typing import Dict, Optional

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import HTTPException
from fastapi.templating import Jinja2Templates

from config import Config


class RequestType(Enum):
    ADD_WHITELIST = "whitelist_add"
    REMOVE_WHITELIST = "whitelist_remove"
    LIST_WHITELIST = "list_whitelist"
    GET_LOG = "get_log"
    GET_STATS = "get_stats"


config = Config.load()


def load_token():
    with open(config.TOKEN_FILE, "r") as f:
        return f.read().strip().encode()


SECRET = load_token()


def compute_hmac(type_, payload):
    obj = {"type": type_, "payload": payload}
    b = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(SECRET, b, hashlib.sha256).hexdigest()


def send_request(obj):
    data = json.dumps(obj, ensure_ascii=False).encode()
    hdr = struct.pack(">I", len(data))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(config.SOCK_PATH)
    s.sendall(hdr + data)
    # recv response
    hdr = s.recv(4)
    if not hdr or len(hdr) < 4:
        s.close()
        return None
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.decode())


def generic_api_request(type_: RequestType, payload: Dict = {}):
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
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/get_logs")
def get_data():
    now = datetime.now()
    attacks_ts = list(
        map(lambda x: x["ts"], generic_api_request(RequestType.GET_LOG)["result"])
    )

    labels = []
    datas = []
    for i in range(config.INTERFACE_DATA_COUNT, -1, -1):
        t1 = now - timedelta(minutes=config.INTERFACE_TIME_INTERVAL_MINUTE * (i + 1))
        t2 = now - timedelta(minutes=config.INTERFACE_TIME_INTERVAL_MINUTE * i)
        cnt = 0
        for at in attacks_ts:
            if t1.timestamp() <= at < t2.timestamp():
                cnt += 1
        labels.append(f"{t1.strftime('%H:%M:%S')} ~ {t2.strftime('%H:%M:%S')}")
        datas.append(cnt)
    return {"labels": labels, "datas": datas}


@app.get("/api/get_attacks")
def get_attacks(limit: int = Query(100, gt=0, le=2000), query: Optional[str] = None):
    attacks = generic_api_request(RequestType.GET_LOG)["result"][-limit:]
    if query:
        q = query.lower()
        filtered = []
        for i in attacks:
            s = (
                (str(i.get("laddr")) or "")
                + ":"
                + (str(i.get("lport")) or "")
                + " "
                + (str(i.get("raddr")) or "")
                + ":"
                + (str(i.get("rport")) or "")
            )
            if q in s.lower():
                filtered.append(i)
        attacks = filtered

    return attacks


@app.get("/api/get_whitelist")
def get_whitelist():
    return generic_api_request(RequestType.LIST_WHITELIST)


@app.post("/api/add_whitelist")
def add_whitelist(ip: str):
    return generic_api_request(RequestType.ADD_WHITELIST, {"ip": ip})


@app.post("/api/remove_whitelist")
def remove_whitelist(ip: str):
    return generic_api_request(RequestType.REMOVE_WHITELIST, {"ip": ip})
