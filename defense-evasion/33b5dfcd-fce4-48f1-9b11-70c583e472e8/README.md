# 33b5dfcd-fce4-48f1-9b11-70c583e472e8 — golden replay datasets

`Rogue Domain Controller - Kerberos DRS SPN Request by Non-DC Host (AN0770)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'target_user_name not_regex .*\Q$\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'service_name contains E3514235-4B06-11D1-AB04-00C04FC2DCD2' — every other condition holds, so the stage gate rejects the events |

## Replaying

These datasets must be replayed onto **`replay-events-sysmon`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-sysmon
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.


## Technique Breakdown

* What it is: Rogue Domain Controller. Adversaries register a rogue Domain Controller (DC) in the Active Directory (AD) environment (a technique commonly known as DCShadow) to inject malicious objects (like changing user passwords, SID history, or group memberships) without triggering standard monitoring controls. This relies on replicating changes directly to the legitimate DC via Active Directory replication protocols. Detection focuses on monitoring directory service additions/modifications (such as `nTDSDSA` object class changes in the configuration partition), unusual DRSUAPI (Directory Replication Service) RPC calls originating from non-DC hosts, or Kerberos ticket requests (Event 4769) for DRS SPNs by non-DC machines.
* Log Source Requirements: Windows Security Event Log Event ID 5136 (AD changes), Event ID 4662 (Object access), or Event ID 4769 (Kerberos ticket requests).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Host logs on the Active Directory Domain Controllers capture Event ID 5136 for object alterations and Event ID 4769 for Kerberos service tickets.
    * NIDS (Suricata + Zeek): YES. Network filters capture DRSUAPI replication calls (such as `DrsReplicaAdd` or `DrsAddEntry`) between non-DC computer IPs and the DC on port 135/rpc.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
