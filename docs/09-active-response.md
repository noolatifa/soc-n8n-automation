# 08 — Active Response: block/unblock IP+port & Rollback

> The Active Response (AR) mechanism executes firewall changes **on the
> monitored VM itself** (Linux, `100.64.0.20`), not on the VM SOC. Protection
> therefore survives a loss of connectivity with the SOC.
>
> Chain: `Wazuh Manager → Active Response → Wazuh Agent → script → iptables`.

---

## 1. Command definitions (`ar.conf`)

```text
block-ip600   - block-ip.sh     - timeout 600
unblock-ip0   - unblock-ip.sh   - timeout 0
block-port600 - block-port.sh   - timeout 600
unblock-port0 - unblock-port.sh - timeout 0
```

| Command | Effect | Timeout semantics |
|---|---|---|
| `block-ip600` | `iptables -I INPUT -s <IP> -j DROP` | auto-expires after 600 s |
| `block-port600` | `iptables -I INPUT -s <IP> -p tcp --dport <PORT> -j DROP` | auto-expires after 600 s |
| `unblock-ip0` | removes **all** matching DROP rules for the IP | on-demand only (rollback) |
| `unblock-port0` | removes the IP:port DROP rule | on-demand only (rollback) |

The `*600` suffix gives a safety net: even if the orchestration layer dies,
a wrong block lifts itself after 10 minutes. The `*0` commands exist
explicitly for the rollback mechanism (see [07-n8n-workflow.md](07-n8n-workflow.md)).

---

## 2. Payload parsing (jq)

Every AR script receives the alert JSON on stdin and extracts its parameters
with `jq`:

```bash
read -r INPUT_JSON
IP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip // .parameters.extra_args[0]')
PORT=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.dstport // .parameters.extra_args[1] // empty')
CORRELATION_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.correlation_id // "none"')
```

`jq` guarantees reliable parsing of nested JSON structures in bash.

---

## 3. `block-ip.sh` — idempotent, locked, state-aware

```bash
#!/bin/bash
STATE_DIR=/var/ossec/active-response/state
mkdir -p "$STATE_DIR"

# 1) Cancellation marker: a rollback was already requested → do NOT block
if [ -f "$STATE_DIR/cancel-$IP" ]; then
  echo "$(date) block cancelled for $IP (rollback marker present)" \
    >> /var/ossec/logs/active-responses.log
  exit 0
fi

# 2) Idempotency: never add a duplicate rule
if sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
  exit 0
fi

# 3) Serialize concurrent executions (one lock per agent)
exec 200>/var/lock/ar-block-ip.lock
flock 200

# 4) Apply and record state
sudo iptables -I INPUT -s "$IP" -j DROP
touch "$STATE_DIR/block-$IP-$CORRELATION_ID"
```

Key properties:

- **`flock`** prevents two concurrent executions from racing on the same
  iptables chain.
- **State markers** (`block-<IP>-<correlation_id>`) let the platform
  distinguish IP actions from port actions and audit what was applied.
- **Cancellation markers** (`cancel-<IP>`) solve the late-block race (see §6).

---

## 4. `block-port.sh` — targeted service blocking

```bash
# Same header as block-ip.sh (parsing, cancel marker, idempotency, flock)
sudo iptables -I INPUT -s "$IP" -p tcp --dport "$PORT" -j DROP
touch "$STATE_DIR/blockport-$IP-$PORT-$CORRELATION_ID"
```

This blocks **one service** from one source, leaving the rest of the traffic
from that IP untouched — the graduated-response strategy.

---

## 5. Unblock scripts — real removal, all occurrences

### 5.1 `unblock-ip.sh`

```bash
# Remove every occurrence of the rule (handles duplicate inserts)
while sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; do
  sudo iptables -D INPUT -s "$IP" -j DROP
done

# Cancellation marker: any *late* block request for this IP will be ignored
touch "$STATE_DIR/cancel-$IP"
```

### 5.2 `unblock-port.sh`

```bash
while sudo iptables -C INPUT -s "$IP" -p tcp --dport "$PORT" -j DROP 2>/dev/null; do
  sudo iptables -D INPUT -s "$IP" -p tcp --dport "$PORT" -j DROP
done
touch "$STATE_DIR/cancelport-$IP-$PORT"
```

The port unblock is scoped to the exact IP:port pair, so an IP rollback never
removes a still-relevant port rule, and vice versa.

---

## 6. Race conditions handled

| Scenario | Mechanism |
|---|---|
| Double block (fast path + IA action) | `iptables -C` idempotency check |
| Concurrent executions | `flock` per script |
| Rollback arrives **before** a late block | `cancel-*` marker makes the late block a no-op |
| Block + rollback interleaved | state markers + loop-until-gone removal |

---

## 7. Logging (multi-source traceability)

Every action leaves traces at five independent levels:

1. **Wazuh Agent** — `/var/ossec/logs/active-responses.log`
2. **Wazuh Manager** — centralized AR journal
3. **System** — `/var/log/auth.log` (sudo invocation of `iptables`)
4. **PostgreSQL** — `pending_actions` row (`pending` / `confirmed` / `rolled_back`)
5. **TheHive** — case created / updated / closed

This redundancy guarantees an action can always be audited even if one
source fails (see [10-postgresql.md](10-postgresql.md)).

---

## 8. Verification

```bash
# Rule in place after a block
sudo iptables -L INPUT -n | grep 198.51.100.55
# DROP  all  --  198.51.100.55  0.0.0.0/0

# System-level proof (sudo trace)
sudo grep "iptables" /var/log/auth.log | tail -5

# After rollback: no rule must remain
sudo iptables -L INPUT -n | grep 12.13.14.15
# (no output)
```

The rollback is considered complete only when **all** proofs agree:
PostgreSQL `rolled_back`, `auth.log` shows `iptables -D`, TheHive case closed
with `FalsePositive` + tag `rolled-back`, and iptables returns no rule
(triple proof, see [07](07-n8n-workflow.md) and [11](11-tests-validation.md)).