# 09 — Ansible Forensics: Controlled Evidence Collection

> Automated response (blocking) limits the impact of an attack but does not
> explain what happened on the impacted machine. A dedicated forensics layer,
> built on **Ansible**, collects artifacts over SSH on the monitored VMs in a
> controlled, reproducible way.
>
> Response and investigation are deliberately separated: response must be
> immediate; investigation may take minutes and produces a structured evidence
> bundle.

---

## 1. Collection chain

```
n8n SSH node (credential: id_n8n)
        │  ssh latifa@100.64.0.11 (VM SOC)
        ▼
ansible-playbook /etc/ansible/playbooks/collect_forensics.yml
        │  ssh user1@<monitored VM>
        ▼
/tmp/evidence_<epoch>/  (ps.txt, netstat.txt, last.txt, auth.log)
```

Ansible runs **from the VM SOC** (`pc1-soc`), where the playbooks, inventory
and configuration live under `/etc/ansible/`.

---

## 2. Playbook `collect_forensics.yml`

```yaml
---
- name: Collect forensic evidence
  hosts: vulnerable_machines
  become: yes

  tasks:
    - name: Create timestamped evidence directory
      file:
        path: "/tmp/evidence_{{ ansible_date_time.epoch }}"
        state: directory
        mode: '0755'
      register: evidence_dir

    - name: Collect full process list
      shell: ps auxf > {{ evidence_dir.path }}/ps.txt

    - name: Collect active network connections
      shell: netstat -tulpn > {{ evidence_dir.path }}/netstat.txt

    - name: Collect recent user logins
      shell: last -20 > {{ evidence_dir.path }}/last.txt

    - name: Collect authentication log excerpts
      shell: tail -100 /var/log/auth.log > {{ evidence_dir.path }}/auth.log

    - name: Verify evidence files
      stat:
        path: "{{ evidence_dir.path }}/{{ item }}"
      loop: [ps.txt, netstat.txt, last.txt, auth.log]

    - name: Show evidence location
      debug:
        msg: "Evidence collected in {{ evidence_dir.path }}"
```

Observed run output:

```text
PLAY RECAP
100.64.0.20 : ok=7    changed=5    unreachable=0    failed=0
```

---

## 3. Privilege escalation setup (and the sudoers pitfall)

Remote tasks require non-interactive privilege escalation on the monitored VM.

### 3.1 The problem
An `/etc/sudoers.d/user1` file created with permissions **644** is rejected by
`sudo` for security reasons, which made every `become: yes` task hang until
timeout.

### 3.2 The fix

```text
# /etc/sudoers.d/user1  — mode 0440, root:root
Defaults:user1 !authenticate
user1 ALL=(ALL) NOPASSWD: ALL
```

```bash
sudo chmod 440 /etc/sudoers.d/user1
sudo chown root:root /etc/sudoers.d/user1
```

And in `ansible.cfg`:

```ini
[privilege_escalation]
become        = True
become_method = sudo
become_flags  = -H -n
```

`-H -n` forces a non-interactive sudo with a clean HOME, matching the
`!authenticate` directive.

---

## 4. Inventory

```ini
[soc]
100.64.0.11 ansible_user=latifa

[vulnerable_machines]
100.64.0.20 ansible_user=user1
```

(Windows endpoints are covered by Sysmon telemetry, see
[06-sysmon-windows.md](06-sysmon-windows.md); the Linux playbook targets the
`vulnerable_machines` group.)

---

## 5. Triggering

### 5.1 Automatic (n8n)
Two SSH nodes — `Run Forensics Playbook` and `Run Forensics Playbook1` —
authenticated with the private key `id_n8n`, execute:

```text
ansible-playbook /etc/ansible/playbooks/collect_forensics.yml
```

They are wired **strictly downstream** of the traceability nodes
(`Alerts - Log AI Block IP/Port`) and of the confirmed-case TheHive update,
guaranteeing that evidence collection only starts once the global state is
stable (see [07-n8n-workflow.md](07-n8n-workflow.md)).

### 5.2 Manual
An analyst can run the same command directly from the VM SOC at any time:

```bash
ansible-playbook /etc/ansible/playbooks/collect_forensics.yml
```

---

## 6. Evidence storage & consultation

Evidence stays on the monitored VM in `/tmp/evidence_<epoch>/` and is
consulted remotely over SSH:

```bash
ssh user1@100.64.0.20 'ls -lh /tmp/evidence_*/'
```

It constitutes an investigation complement **independent** of the TheHive
case: even if the case is closed or rolled back, the raw artifacts remain
available for later analysis.

---

## 7. Validation

```bash
# From the VM SOC
ansible-playbook /etc/ansible/playbooks/collect_forensics.yml
# → PLAY RECAP ok=7 changed=5

ssh user1@100.64.0.20 'cat /tmp/evidence_*/netstat.txt | head'
```

Expected: the four artifacts exist with fresh timestamps, and the n8n
execution log shows the SSH node completing successfully after the
traceability nodes.