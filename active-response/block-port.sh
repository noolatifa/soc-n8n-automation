#!/bin/bash
#
# Active Response: block-port.sh
# Blocks a specific IP:port combination via iptables for 600 seconds.
#

ACTION=$1
USER=$2
IP=$3
PORT=$4

if [ "${ACTION}" != "add" ]; then
   exit 0
fi

read -r INPUT_JSON
CORRELATION_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.correlation_id // "none"')

STATE_DIR=/var/ossec/active-response/state
mkdir -p "${STATE_DIR}"

# Cancellation marker check
if [ -f "${STATE_DIR}/cancelport-${IP}-${PORT}" ]; then
    echo "$(date) block-port cancelled for ${IP}:${PORT}" \
        >> /var/ossec/logs/active-responses.log
    exit 0
fi

# Idempotency
if iptables -C INPUT -s "${IP}" -p tcp --dport "${PORT}" -j DROP 2>/dev/null; then
    exit 0
fi

exec 200>/var/lock/ar-block-port.lock
flock 200

iptables -I INPUT -s "${IP}" -p tcp --dport "${PORT}" -j DROP
touch "${STATE_DIR}/blockport-${IP}-${PORT}-${CORRELATION_ID}"

echo "$(date) block-port.sh: ${IP}:${PORT} blocked (corr=${CORRELATION_ID})" \
    >> /var/ossec/logs/active-responses.log

exit 0