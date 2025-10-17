from datetime import datetime, timedelta
from re import I
import socket, json, struct, hmac, hashlib, os, sys

from fastapi.exceptions import HTTPException

from config import Config
from fastapi import FastAPI, Query, Request
from typing import List, Optional
from fastapi.templating import Jinja2Templates
import time

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


# helpers
def whitelist_add(ip):
    tp = "whitelist_add"
    payload = {"ip": ip}
    req = {"type": tp, "payload": payload, "hmac": compute_hmac(tp, payload)}
    return send_request(req)


def whitelist_remove(ip):
    tp = "whitelist_remove"
    payload = {"ip": ip}
    req = {"type": tp, "payload": payload, "hmac": compute_hmac(tp, payload)}
    return send_request(req)


def list_whitelist():
    tp = "list_whitelist"
    payload = {}
    req = {"type": tp, "payload": payload, "hmac": compute_hmac(tp, payload)}
    return send_request(req)


def get_log():
    tp = "get_log"
    payload = {}
    req = {"type": tp, "payload": payload, "hmac": compute_hmac(tp, payload)}
    return send_request(req)


def get_stats():
    tp = "get_stats"
    payload = {}
    req = {"type": tp, "payload": payload, "hmac": compute_hmac(tp, payload)}
    return send_request(req)


app = FastAPI()


templates = Jinja2Templates(directory="./templates")


@app.get("/")
def main_page(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/get_logs")
def get_data():
    now = datetime.now()
    attacks_ts=list(map(lambda x: x["ts"], get_log()["result"]))

    labels=[]
    datas=[]
    for i in range(config.INTERFACE_DATA_COUNT, -1, -1):
        t1 = now - timedelta(minutes=config.INTERFACE_TIME_INTERVAL_MINUTE * (i+1))
        t2 = now - timedelta(minutes=config.INTERFACE_TIME_INTERVAL_MINUTE * i)
        cnt=0
        for at in attacks_ts:
            if t1.timestamp() <= at < t2.timestamp():
                cnt+=1
        labels.append(f"{t1.strftime('%H:%M:%S')} ~ {t2.strftime('%H:%M:%S')}")
        datas.append(cnt)
    return {"labels":  labels, "datas":datas}


@app.get("/api/get_attacks")
def get_attacks(limit: int = Query(100, gt=0, le=2000), query: Optional[str] = None):
    attacks=get_log()["result"][-limit:]
    if query:
        q=query.lower()
        filtered=[]
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
        attacks=filtered
    
    return attacks
