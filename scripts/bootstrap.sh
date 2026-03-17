#!/usr/bin/env bash
# Purple Team Lab — Bootstrap Script
# Sets up the environment, seeds initial data, and starts the stack.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Purple Team Lab Bootstrap ==="
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "[!] Docker not found. Install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker compose &>/dev/null && ! command -v docker-compose &>/dev/null; then
    echo "[!] Docker Compose not found."
    exit 1
fi

# Determine compose command
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    COMPOSE="docker-compose"
fi

cd "$PROJECT_DIR"

# Create log staging directories
echo "[+] Creating log staging directories..."
mkdir -p /tmp/purple-team-logs/{cloudtrail,vpc_flow,guardduty,falco,waf,dns}

# Link dac_modules from cloud-sec-blog if available
DAC_PATH=""
if [ -d "../csb/dac_modules" ]; then
    DAC_PATH="../csb/dac_modules"
    echo "[+] Found dac_modules at $DAC_PATH — will mount for scenario loading"
elif [ -d "../cloud-sec-blog/dac_modules" ]; then
    DAC_PATH="../cloud-sec-blog/dac_modules"
    echo "[+] Found dac_modules at $DAC_PATH"
else
    echo "[!] No dac_modules found — generator will use built-in scenarios"
    echo "    To use your detections, clone jackiecloudsec-blog next to this repo"
fi

# Create .env file for docker-compose
cat > .env <<EOF
SPLUNK_PASSWORD=PurpleTeam2026!
MINIO_ROOT_USER=purpleadmin
MINIO_ROOT_PASSWORD=PurpleTeam2026!
EOF

# If dac_modules found, add a volume mount override
if [ -n "$DAC_PATH" ]; then
    DAC_ABS="$(cd "$DAC_PATH" && pwd)"
    cat > docker-compose.override.yml <<EOF
version: "3.8"
services:
  generator:
    volumes:
      - log-staging:/var/log/purple-team
      - ./generator:/opt/generator
      - ${DAC_ABS}:/opt/dac_modules:ro
EOF
    echo "[+] Created docker-compose.override.yml with dac_modules mount"
fi

# Build and start
echo ""
echo "[+] Building containers..."
$COMPOSE build

echo ""
echo "[+] Starting stack..."
$COMPOSE up -d

echo ""
echo "[+] Waiting for Splunk to be healthy (this takes ~2 minutes on first start)..."
timeout=180
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if $COMPOSE exec -T splunk curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 2>/dev/null | grep -q "200\|303"; then
        echo "[+] Splunk is ready!"
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo "    Waiting... ($elapsed/$timeout seconds)"
done

if [ $elapsed -ge $timeout ]; then
    echo "[!] Splunk didn't start in time. Check: $COMPOSE logs splunk"
    exit 1
fi

echo ""
echo "=== Purple Team Lab is Running ==="
echo ""
echo "  Splunk Web:      http://localhost:8000"
echo "    Username:      admin"
echo "    Password:      PurpleTeam2026!"
echo ""
echo "  MinIO Console:   http://localhost:9001"
echo "    Username:      purpleadmin"
echo "    Password:      PurpleTeam2026!"
echo ""
echo "  Log Generator:   Producing events every 30 seconds"
echo "    Logs staging:  /tmp/purple-team-logs/"
echo ""
echo "  Indexes:  cloudtrail | vpc_flow | guardduty | falco | waf | dns"
echo ""
echo "  Try in Splunk:"
echo "    index=cloudtrail | stats count by eventName"
echo "    index=vpc_flow action=\"REJECT\" | stats count by srcAddr"
echo "    index=guardduty severity>=7 | table _time type severity description"
echo ""
echo "  Stop:    $COMPOSE down"
echo "  Logs:    $COMPOSE logs -f generator"
echo "  Restart: $COMPOSE restart"
