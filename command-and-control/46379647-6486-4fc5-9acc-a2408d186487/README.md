### Technique Breakdown

* What it is: Multi-Stage Channels. Adversaries use multiple command and control channels to segment their activity. A first-stage channel (typically a script, HTA, or light loader) connects to a remote server to download secondary tooling. Once executed, the second-stage process (often a more robust RAT or beacon) establishes outbound connections to a completely different, unrelated destination. This isolates command infrastructure and complicates analysis.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures process creation. Event ID 3 logs outbound network connections.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 3 (network_connection)
    - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
