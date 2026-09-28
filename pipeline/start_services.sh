#!/usr/bin/env bash
# vLLM + CheckPC pipeline server v3.69-rc17
set -euo pipefail

ANALYSIS_DIR="${CHECKPC_ANALYSIS_DIR:-/opt/llm/analysis-current}"
PYTHON="${CHECKPC_PYTHON:-/opt/llm/vllm/venv/bin/python}"
VLLM_START="${CHECKPC_VLLM_START:-/opt/llm/vllm/start_vllm.sh}"

mkdir -p /var/log
echo "[INFO] Python: $PYTHON ($($PYTHON -c 'import sys; print(sys.executable)'))"

echo "[1/2] vLLM を起動..."
nohup "$VLLM_START" > /var/log/vllm.log 2>&1 &
echo "      PID: $!"

# 固定sleepだけに依存せず、最大60秒のreadiness確認を行う。
VLLM_READY=0
for _ in $(seq 1 60); do
  if "$PYTHON" - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8000/v1/models", timeout=1).read()
PY
  then
    VLLM_READY=1
    break
  fi
  sleep 1
done
if [[ "$VLLM_READY" != "1" ]]; then
  echo "[ERROR] vLLM readiness failed after 60 seconds" >&2
  tail -n 50 /var/log/vllm.log >&2 || true
  exit 1
fi

if [[ -n "${PIPELINE_SSL_CERT:-}" && -n "${PIPELINE_SSL_KEY:-}" ]]; then
  PORT="${PIPELINE_PORT:-${PIPELINE_HTTPS_PORT:-443}}"
  SCHEME=https
else
  PORT="${PIPELINE_PORT:-${PIPELINE_HTTP_PORT:-8001}}"
  SCHEME=http
fi

echo "[2/2] パイプラインサーバーを起動（${SCHEME}:${PORT}）..."
"$PYTHON" "$ANALYSIS_DIR/pipeline_doctor.py" --skip-vllm
nohup "$PYTHON" "$ANALYSIS_DIR/server.py" > /var/log/pipeline-server.log 2>&1 &
echo "      PID: $!"

echo ""
echo "起動完了"
echo "  vLLM: http://localhost:8000"
echo "  UI:    ${SCHEME}://${PIPELINE_BIND_HOST:-127.0.0.1}:${PORT}/"
echo ""
echo "ログ: tail -f /var/log/vllm.log /var/log/pipeline-server.log"
