#!/bin/bash
#
# Active Response: unblock-port.sh
# Removes the iptables DROP rule for a specific IP:port combination.
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

while iptables -C INPUT -s "${IP}" -p tcp --dport "${PORT}" -j DROP 2>/dev/null; do
    iptables -D INPUT -s "${IP}" -p tcp --dport "${PORT}" -j DROP
done

touch "${STATE_DIR}/cancelport-${IP}-${PORT}"