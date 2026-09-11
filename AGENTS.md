# AGENTS.md

## Project

DNS Tunneling IDS/IPS detection and defense project.

## Architecture

DNS Packet Capture
→ Snort Rule Detection
→ Scapy Behavior Analysis
→ Risk Score Engine
→ SIEM Log
→ IP Blacklist / Domain Sinkhole / iptables Block

## Security Rules

- Do not write exploit code.
- Do not automate dnscat2 execution.
- Do not connect to external C2 infrastructure.
- Do not add attack automation.
- Do not use shell=True.
- Do not store packet objects in queues.
- Do not add offensive payload generation.
- Use iptables only for internal lab defense.

## Live Engine Rules

- File: engine/live_soar_engine.py
- Allowed external packages: scapy, regex only.
- Do not import Python re.
- Do not import logging.
- process_packet must not access DB.
- process_packet must not compute entropy.
- process_packet must not run regex.
- process_packet must not call subprocess.
- process_packet must not call urllib.
- process_packet must only normalize qname, extract src_ip, create primitive dict, enqueue copy.

## Offline Analyzer Rules

- File: scripts/dns_analyzer.py
- Allowed packages: scapy, pandas, matplotlib, pyyaml, regex.
- Analyze pcap files only.
- NXDOMAIN must be calculated from DNS response rcode.
- Do not perform blocking from offline analyzer.

## Risk Engine Rules

- File: scripts/risk_engine.py
- Combine offline analyzer results, Snort alerts, domain blacklist, IP blacklist.
- Save results/detection_result.csv and results/detection_result.json.
- Include risk score breakdown.
- Response actions (block/notify) must come from the shared playbook (scripts/playbook.py +
  playbooks/dns_tunneling_response.yaml), not from a hardcoded verdict-to-action mapping.

## Playbook Rules

- Files: scripts/playbook.py (loader/matcher), playbooks/*.yaml (condition → action rules).
- Shared by both scripts/risk_engine.py (offline) and engine/live_soar_engine.py (live); do not
  fork a second implementation of severity classification or rule matching.
- Condition matching is limited to severity-level comparison (NORMAL/SUSPICIOUS/MALICIOUS/CRITICAL).
- Do not use eval/exec or any dynamic-expression DSL for condition matching.
- Action execution stays engine-specific: live executes immediately (with TTL), offline only
  executes block_ip when `--block`/`--live` are passed (default is advisory/dry-run).
- New action types must be added as a named handler (closed registry), never as an arbitrary
  callable loaded from config.

## Defense Script Rules

- Validate IP/domain input.
- Avoid duplicate iptables rules.
- Keep modes:
  - kali_input
  - ubuntu_output
  - gateway_forward
- Log block/unblock actions to results/block_rules.log.
