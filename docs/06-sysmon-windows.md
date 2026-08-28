# 06 — Windows Agent + Sysmon

> The **monitored Windows VM** (`100.64.0.21`) runs the Wazuh agent natively,
> plus **Sysmon** for deep Windows telemetry. Sysmon events are shipped to the
> Wazuh Manager (VM SOC, `100.64.0.11`) through the `eventchannel` log format.

---

## 1. Installation

### 1.1 Wazuh agent (Windows)

```powershell
msiexec /i wazuh-agent-4.14.6-1.msi /q WAZUH_MANAGER="100.64.0.11"
```

The agent enrolls on port **1515** and communicates on port **1514**, exactly
like the Linux agent (see [04-wazuh.md](04-wazuh.md)).

### 1.2 Sysmon

```powershell
# Install with the lab configuration
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Later, update the configuration without reinstalling
.\Sysmon64.exe -c sysmonconfig.xml
```

---

## 2. Sysmon configuration (`sysmonconfig.xml`)

The configuration is deliberately **selective**: it captures the events with
the highest detection value while keeping noise low.

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- E1: process creation (command line + hashes) -->
    <ProcessCreate onmatch="exclude">
      <Image condition="end with">\svchost.exe</Image>
      <Image condition="end with">\MsMpEng.exe</Image>
    </ProcessCreate>

    <!-- E3: network connections (reverse shells, C2) -->
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">\svchost.exe</Image>
      <DestinationPort condition="is">135</DestinationPort>
    </NetworkConnect>

    <!-- E7: suspicious module loading -->
    <ImageLoad onmatch="include">
      <Image condition="contains">powershell</Image>
      <Image condition="contains">office</Image>
    </ImageLoad>

    <!-- E11: persistence via startup folders -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Start Menu\</TargetFilename>
      <TargetFilename condition="contains">\Startup\</TargetFilename>
    </FileCreate>

    <!-- E13: persistence via Run keys -->
    <RegistryValueSet onmatch="include">
      <TargetObject condition="contains">\Run</TargetObject>
      <TargetObject condition="contains">\RunOnce</TargetObject>
    </RegistryValueSet>

    <!-- E23: file deletion (anti-forensics) -->
    <FileDelete onmatch="include">
      <TargetFilename condition="contains">\Temp\</TargetFilename>
    </FileDelete>

  </EventFiltering>
</Sysmon>
```

| Event ID | Telemetry | Typical detection use |
|---|---|---|
| 1 | Process creation (CLI, hashes) | Encoded PowerShell, `cmd /c`, LOLBins |
| 3 | Network connection | Reverse shells, C2 beaconing |
| 7 | Image loaded | DLL sideloading, reflective loading |
| 11 | File created | Droppers, startup persistence |
| 13 | Registry value set | `Run`/`RunOnce` persistence |
| 23 | File deleted | Anti-forensics, cleanup after execution |

---

## 3. Ingestion into Wazuh

On the Windows VM, the agent is configured to read the Sysmon operational
channel:

```xml
<!-- C:\Program Files (x86)\ossec-agent\ossec.conf -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Each Sysmon event is decoded by Wazuh's Windows rule set (process creation,
registry, network) and forwarded to the Manager on port 1514. From there it
follows the standard pipeline: level scoring → threshold ≥ 6 → webhook n8n →
RabbitMQ → workflow (see [04](04-wazuh.md) and [07](07-n8n-workflow.md)).

Combined with Suricata on the Linux VM, this gives **cross-host visibility**:
a network alert on one endpoint can be correlated with process-level evidence
on the other.

---

## 4. Validation

```powershell
# Sysmon is alive and logging
wevtutil qe Microsoft-Windows-Sysmon/Operational /c:5 /f:text

# Wazuh agent service
Get-Service -Name WazuhSvc
```

On the VM SOC, the Wazuh Dashboard must show the Windows agent as `active`,
and security events tagged with Sysmon rule IDs (e.g. `60000`–`60120` range)
must appear for `100.64.0.21`.

```bash
# From the VM SOC
curl -sk -u <user>:<pass> "https://100.64.0.11:55000/agents?status=active"
```

A working test: run `powershell -enc <base64>` on the Windows VM → expect a
Sysmon Event 1, a Wazuh alert on the dashboard, and the event entering the
n8n pipeline if its level is ≥ 6.