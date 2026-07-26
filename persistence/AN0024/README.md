### Technique Breakdown

* What it is: Event Triggered Execution: WMI Event Subscription. Windows Management Instrumentation (WMI) can be used to register event filters, event consumers, and filter-to-consumer bindings. When a specific system event triggers the filter (e.g., system startup, time elapsed, or user logon), the WMI service executes the consumer (e.g., CommandLineEventConsumer or ActiveScriptEventConsumer) with local system (SYSTEM) privileges. Adversaries exploit WMI event subscriptions to establish persistent, elevated execution flows.
* Log Source Requirements: Endpoint logs capturing process creation and command line arguments, and WMI event subscription logs.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs CLI invocations of wmic.exe or PowerShell cmdlets modifying WMI objects. Sysmon Event IDs 19, 20, and 21 log raw WMI consumer/filter additions.
  - NIDS (Suricata + Zeek): NO. WMI event subscription registration is a local OS management task.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event IDs 19/20/21 (wmi_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
