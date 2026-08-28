#!/bin/bash
#
# Active Response: unblock-ip.sh
# Removes all iptables DROP rules for the given IP.
# Used explicitly by the rollback mechanism (timeout 0).
#

ACTION=$1
USER=$2
IP=$3

if [ "${ACTION}" != "add" ]; then
   exit 0
fi

read -r INPUT_JSON
CORRELATION_ID=$(echo "${INPUT_JSON}" | jq -r '.parameters.alert.correlation_id // "none"')

STATE_DIR=/var/ossec/active-response/state
mkdir -p "${STATE_DIR}"

# Remove every occurrence of the rule (handles duplicate inserts)
while iptables -C INPUT -s "${IP}" -j DROP 2>/dev/null; do
    iptables -D INPUT -s "${IP}" -j DROP
done

# Cancellation marker: any *late* block request for this IP will be ignored
touch "${STATE_DIR}/cancel-${IP}"

echo "$(date) unblock-ip.sh: IP ${IP} unblocked (corr=${CORRELATION_ID})" \
    >> /var/ossec/logs/active-responses.log

exit 0