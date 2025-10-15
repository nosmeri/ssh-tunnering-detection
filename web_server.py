from datetime import datetime, timedelta
import socket, json, struct, hmac, hashlib, os, sys

from fastapi.responses import HTMLResponse
from config import Config
from fastapi import FastAPI, Request
from typing import List
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


def send(cmd, argv=[]):
    # 간단 테스트 CLI
    if cmd == "add" and len(argv) == 3:
        return(whitelist_add(argv[2]))
    elif cmd == "rm" and len(argv) == 3:
        return(whitelist_remove(argv[2]))
    elif cmd == "list":
        return(list_whitelist())
    elif cmd == "log":
        return(get_log())
    elif cmd == "stats":
        return(get_stats())
    else:
        return("usage: add <ip> | rm <ip> | list | log | stats")


app = FastAPI()


templates = Jinja2Templates(directory="./templates")


@app.get("/")
def main_page(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/getdata")
def get_data():
    now = datetime.now()
    attacks_ts=list(map(lambda x: x["ts"], send("log")["result"]))

    labels=[]
    datas=[]
    for i in range(30, -1, -1):
        t1 = now - timedelta(minutes=1 * (i+1))
        t2 = now - timedelta(minutes=1 * i)
        cnt=0
        for at in attacks_ts:
            if t1.timestamp() <= at < t2.timestamp():
                cnt+=1
        labels.append(f"{t1.strftime('%H:%M:%S')} ~ {t2.strftime('%H:%M:%S')}")
        datas.append(cnt)
    return {"labels":  labels, "datas":datas}
