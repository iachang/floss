#!/usr/bin/env bash
set -euo pipefail

CR=1

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <ALONE> [RANK] [PARTIES_IPS]"
  echo "  ALONE=1: single party (RANK and PARTIES_IPS optional)"
  echo "  ALONE=0: multi-party (RANK and PARTIES_IPS required)"
  echo "Example:"
  echo "  $0 1"
  echo "  $0 0 0 172.31.10.235:39530,172.31.4.106:39531"
  exit 1
fi

if [[ $1 == "0" ]]; then
  ALONE=0
  if [[ $# -lt 3 ]]; then
    echo "When ALONE=0, RANK and PARTIES_IPS are required."
    echo "Usage: $0 0 <RANK> <PARTIES_IPS>"
    exit 1
  fi
  RANK="$2"
  PARTIES_IPS="$3"
else
  ALONE=1
  RANK="${2:-0}"
  PARTIES_IPS="${3:-}"
fi

if [[ $ALONE -eq 0 ]]; then
  BIG_POWERS=(8 9 10 11 12 13 14 15 16 18 20)
else
  BIG_POWERS=(8 9 10 11 12 13 14 15 16)
fi

extract_time() {
  grep -oE '\(or[[:space:]]+[0-9.]+[[:space:]]+s\)' | grep -oE '[0-9.]+' | tail -n 1
}

extract_bytes_sent() {
  grep -oE 'send bytes:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -n 1
}

extract_bytes_recv() {
  grep -oE 'recv bytes:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -n 1
}


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../MOSAC"

for SMALL_POWER in 4; do
  OUT_CSV="shuffle_opmcc_offline.csv"
  OUT_CSV_ONLINE="shuffle_opmcc_online.csv"

  # Write header (overwrite per SmallPower)
  echo "InputSize,OfflinePrepTime,TotalTime,BytesSent,BytesRecv" > "$OUT_CSV"
  echo "InputSize,OnlineTime,BytesSent,BytesRecv" > "$OUT_CSV_ONLINE"

  for BIG_POWER in "${BIG_POWERS[@]}"; do
    echo "== Offline: small_power=$SMALL_POWER big_power=$BIG_POWER =="

    if [[ $ALONE -eq 0 ]]; then
      OFF_OUTPUT=$(bazel run -c opt //mosac/example:NDSS_offline_example -- \
        --alone=$ALONE --rank=$RANK --parties=$PARTIES_IPS --small_power=$SMALL_POWER --big_power=$BIG_POWER --CR=$CR 2>&1)
    else
      OFF_OUTPUT=$(bazel run -c opt //mosac/example:NDSS_offline_example -- \
        --alone=$ALONE --small_power=$SMALL_POWER --big_power=$BIG_POWER --CR=$CR 2>&1)
    fi

    OFF_TIME=$(echo "$OFF_OUTPUT" | extract_time || true)
    OFF_BYTES_SENT=$(echo "$OFF_OUTPUT" | extract_bytes_sent || true)
    OFF_BYTES_RECV=$(echo "$OFF_OUTPUT" | extract_bytes_recv || true)

    if [[ -z "${OFF_TIME:-}" ]]; then
      echo "ERROR: Failed to extract OfflineTime (small=$SMALL_POWER big=$BIG_POWER)"
      echo "$OFF_OUTPUT" >&2
      exit 1
    fi

    if [[ -z "${OFF_BYTES_SENT:-}" || -z "${OFF_BYTES_RECV:-}" ]]; then
      echo "ERROR: Failed to extract offline byte counters"
      echo "$OFF_OUTPUT" >&2
      exit 1
    fi

    echo "== Online:  small_power=$SMALL_POWER big_power=$BIG_POWER =="

    if [[ $ALONE -eq 0 ]]; then
      ON_OUTPUT=$(bazel run -c opt //mosac/example:NDSS_online_example -- \
        --alone=$ALONE --rank=$RANK --parties=$PARTIES_IPS --small_power=$SMALL_POWER --big_power=$BIG_POWER --cache=0 --CR=0 2>&1)
    else
      ON_OUTPUT=$(bazel run -c opt //mosac/example:NDSS_online_example -- \
        --alone=$ALONE --small_power=$SMALL_POWER --big_power=$BIG_POWER --cache=0 --CR=0 2>&1)
    fi

    ON_TIME=$(echo "$ON_OUTPUT" | extract_time || true)
    ON_BYTES_SENT=$(echo "$ON_OUTPUT" | extract_bytes_sent || true)
    ON_BYTES_RECV=$(echo "$ON_OUTPUT" | extract_bytes_recv || true)

    if [[ -z "${ON_TIME:-}" ]]; then
      echo "ERROR: Failed to extract OnlineTime (small=$SMALL_POWER big=$BIG_POWER)"
      echo "$ON_OUTPUT" >&2
      exit 1
    fi

    if [[ -z "${ON_BYTES_SENT:-}" || -z "${ON_BYTES_RECV:-}" ]]; then
      echo "ERROR: Failed to extract online byte counters"
      echo "$ON_OUTPUT" >&2
      exit 1
    fi

    echo "${BIG_POWER},${ON_TIME},${ON_BYTES_SENT},${ON_BYTES_RECV}" >> "$OUT_CSV_ONLINE"

    TOTAL_TIME=$(python3 - <<PY
print(float("$OFF_TIME") + float("$ON_TIME"))
PY
)

    TOTAL_BYTES_SENT=$((OFF_BYTES_SENT + ON_BYTES_SENT))
    TOTAL_BYTES_RECV=$((OFF_BYTES_RECV + ON_BYTES_RECV))

    echo "${BIG_POWER},${OFF_TIME},${TOTAL_TIME},${TOTAL_BYTES_SENT},${TOTAL_BYTES_RECV}" >> "$OUT_CSV"


    echo "Recorded → $OUT_CSV : BigPower=$BIG_POWER Offline=$OFF_TIME Total=$TOTAL_TIME Sent=$TOTAL_BYTES_SENT Recv=$TOTAL_BYTES_RECV"
  done
done
