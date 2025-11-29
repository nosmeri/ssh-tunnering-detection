# SSH Tunneling Detector

A real-time detection system for potential SSH tunneling attacks, featuring heuristic analysis and a modern web dashboard.

## Setup & Configuration

### 1. Generate Authentication Token

The detector and web server communicate via a secure Unix socket using HMAC authentication. You must generate a shared secret token.

```bash
sudo openssl rand -hex 32 > ./token

# Set permissions (replace pid:gid with your actual user and group)
sudo chown pid:gid /etc/sshdetector/token
sudo chmod 660 /etc/sshdetector/token
```

> **Note**: Ensure the `TOKEN_FILE` path in `config.json` (or `config.py`) matches where you place the token. By default, it looks for `./token`.

### 2. Install Dependencies

This project uses `uv` for dependency management.

```bash
uv sync
```

## Usage

### Run the Detector

The detector requires `root` privileges to capture network traffic (sniffing) and monitor process connections.

```bash
sudo uv run detector.py
```

### Run the Web Interface

The web interface provides a dashboard to view detected attacks and manage the whitelist.

```bash
uv run uvicorn web_server:app --host 0.0.0.0 --port 8000
```

Access the dashboard at: <http://localhost:8000>

**Features:**

- **Graph Interval**: Select time intervals (1m, 5m, 10m, 30m, 1h) for the trend graph.
- **Attack Limit**: Configure the number of displayed attacks (50 - 1000).
- **Mitigation Controls**: Real-time toggle for auto-mitigation.
- **Banned Logs**: History of automatically terminated connections.

## Detection Logic

The system scores SSH connections based on several heuristics:

- **Port Usage**: Non-standard ports (not 22).
- **Duration**: Long-running connections.
- **Traffic Patterns**:
  - **Interactive**: High frequency of small packets (e.g., shell usage).
  - **Bulk**: High frequency of large packets (e.g., SCP, Port Forwarding).
- **Arguments**: Detection of `-R`, `-D`, `-L` flags in process command lines.

## Configuration

Configuration is managed via `config.json` (generated from `config.py` on first run). You can tune scoring thresholds and file paths there.

### Automated Mitigation

The system can automatically terminate SSH processes that exceed a critical score.

- **Enable/Disable**: Toggle "Automated Mitigation" in the web UI.
- **Critical Score**: Set `CRITICAL_SCORE` in `config.py` (default: 1000).
- **History**: View blocked connections in the "Mitigation History" table.
