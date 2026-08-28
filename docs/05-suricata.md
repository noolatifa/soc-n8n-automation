# 05 — Suricata NIDS

> Suricata runs **natively** (not containerized) on the **monitored Linux VM**
> (`vulnerable-machine-linux`, `100.64.0.20`). It listens on the Tailscale
> interface `tailscale0` and feeds the Wazuh agent with EVE JSON events.

---

## 1. Installation (monitored Linux VM)

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata jq
sudo suricata-update
sudo systemctl enable suricata --now
```

Validation:

```bash
sudo systemctl status suricata
sudo suricata -T              # config check
sudo suricatasc               # runtime stats (live)
```

---

## 2. Network configuration

### 2.1 Monitored interface

```yaml
af-packet:
  - interface: tailscale0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
```

The Tailscale interface is used so that Suricata sees **all** inter-VM traffic
of the overlay network, without requiring a SPAN port or a tap.

### 2.2 `HOME_NET`

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.239.0/24, 100.64.0.11/32, 100.64.0.13/32, 100.64.0.14/32, 100.64.0.20/32, 100.64.0.21/32]"
    EXTERNAL_NET: "!$HOME_NET"
```

| IP | Node |
|---|---|
| `100.64.0.11` | VM SOC |
| `100.64.0.13` | VM CTI |
| `100.64.0.14` | VM AI |
| `100.64.0.20` | Monitored VM (Linux) |
| `100.64.0.21` | Monitored VM (Windows) |

This split lets Suricata apply **different rule logic** depending on whether
the source belongs to the internal mesh or not.

### 2.3 Inspected protocols

| Protocol | Default port |
|---|---|
| HTTP | 80 |
| TLS / HTTPS | 443 |
| SSH | 22 |
| DNS | 53 |
| SMB | 445 |
| FTP | 21 |
| DHCP | 67 / 68 |
| DNP3 | 20000 |
| Modbus | 502 |

Industrial protocols (DNP3, Modbus) are included to extend coverage beyond
typical office environments.

---

## 3. Detection profile

```yaml
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

flow:
  memcap: 128mb
stream:
  memcap: 64mb
  reassembly:
    memcap: 256mb
```

A deep-inspection profile is chosen over raw throughput: the lab traffic volume
is modest and the priority is detection accuracy.

---

## 4. Logging — EVE JSON

The `eve-log` output is the single integration point with Wazuh.

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - smb
        - ftp
        - dhcp
        - anomaly
        - stats
```

Output files live in `/var/log/suricata/`:

| File | Purpose |
|---|---|
| `eve.json` | Structured events (integration with Wazuh) |
| `fast.log` | Human-readable alert summary |
| `suricata.log` | Engine operational log |

---

## 5. Custom rules (`local.rules`)

Two example custom rules shipped with the lab:

### 5.1 Nmap SYN scan

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Nmap SYN scan"; \
  flags:S; threshold:type both, track by_src, count 20, seconds 5; \
  classtype:attempted-recon; sid:1000001; rev:1;)
```

Triggers when a single external source opens **20+** distinct TCP connections
with only the `SYN` flag within 5 seconds — typical of a Nmap SYN scan.

### 5.2 Reverse shell detection

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL reverse shell \
  (/bin/sh)"; content:"/bin/sh"; content:"-i"; distance:0; within:10; \
  classtype:trojan-activity; sid:1000002; rev:1;)
```

Matches outbound TCP sessions containing `/bin/sh -i` — a common pattern in
reverse shells.

Custom rules live in `/var/lib/suricata/rules/local.rules` and are loaded via
`suricata.yaml`. After any change:

```bash
sudo systemctl reload suricata
```

---

## 6. Integration with Wazuh

On the monitored VM, the Wazuh agent is configured to ingest `eve.json`:

```xml
<!-- /var/ossec/etc/ossec.conf on the monitored VM -->
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```

The agent parses each JSON event, applies its decoders, and forwards the
resulting alert to the Wazuh Manager on port **1514**. From there, the alert
follows the standard Wazuh → n8n pipeline (see [04-wazuh.md](04-wazuh.md)).

Benefits of this loose coupling (Suricata → file → agent):

- Suricata and Wazuh evolve independently.
- No restart required to reconfigure either side.
- Events can be archived and replayed.

---

## 7. Validation

```bash
# Engine health
sudo systemctl status suricata
sudo tail -n 5 /var/log/suricata/fast.log

# Live JSON stream
sudo tail -f /var/log/suricata/eve.json | jq .event_type

# Custom rules loaded?
sudo grep "sid:100000[12]" /var/lib/suricata/rules/local.rules
```

A working test:

```bash
# From an external host, scan the monitored VM
nmap -sS -T4 100.64.0.20
```

Expected: Suricata emits an `alert` event with `sid:1000001` in `eve.json`,
the Wazuh Dashboard shows the corresponding event, and the n8n pipeline
receives the forwarded alert.