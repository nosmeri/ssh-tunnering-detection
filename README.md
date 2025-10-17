```
sudo openssl rand -hex 32 > ./token

sudo chown pid:gid /etc/sshdetector/token
sudo chmod 660 /etc/sshdetector/token
```

```
sudo uv run main.py

uv run uvicorn web_server:app
```