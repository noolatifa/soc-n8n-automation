#!/bin/bash
#
# Active Response: block-ip.sh
# Blocks an IP via iptables for 600 seconds (managed by Wazuh AR timeout).
#

ACTION=$1
USER=$2
IP=$3
pwd

if [ "${ACTION}" != "add" ]; then
   exit 0
fi

# Extract correlation_id from stdin JSON
read -r INPUT_JSON
CORRELATION_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.correlation_id // "none"')

STATE_DIR=/var/ossec/active-response/state
mkdir -p "${STATE_DIR}"

# 1) Cancellation marker: a rollback was already requested -> do NOT block
if [ -f "${STATE_DIR}/cancel-${IP}" ]; then
    echo "$(date) block cancelled for ${IP} (rollback marker present)" \
        >> /var/ossec/logs/active-responses.log
    exit 0
fi

# 2) Idempotency: never add a duplicate rule
if iptables -C INPUT -s "${IP}" -j DROP 2>/dev/null; then
    exit 0
fi

# 3) Serialize concurrent executions (one lock per agent)
exec 200>/var/lock/ar-block-ip.lock
flock 200

# 4) Apply and record state
iptables -I INPUT -s "${IP}" -j DROP
touch "${STATE_DIR}/block-${IP}-${CORRELATION_ID}"

echo "$(date) block-ip.sh: IP ${IP} blocked (corr=${CORRELATION_ID})" \
    >> /var/ossec/logs/active-responses.log

exit 0