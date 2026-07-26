### Technique Breakdown

* What it is: Email Collection: Email Forwarding Rule. Adversaries may configure email forwarding or inbox rules within a compromised user's mailbox to automatically redirect incoming emails to an external address controlled by the attacker. They establish these rules using PowerShell Exchange cmdlets (such as `New-InboxRule`, `Set-InboxRule`) or via Exchange Management Shell / Exchange Online. Detection monitors execution of these cmdlets with forwarding-specific flags.
* Log Source Requirements: Windows Security Event Log Event ID 4688, Sysmon process creation logs (Event ID 1), or PowerShell Script Block Logging (Event ID 4104) capturing Exchange mailbox configuration commands.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing cmdline parameters that construct forwarding rules. PowerShell script block logging audits exact parameters.
    * NIDS (Suricata + Zeek): NO. Local execution of cmdlets is a host-only management activity.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
