### Technique Breakdown
* What it is: Query Public AI Services. Adversaries or employees query public generative AI systems (like ChatGPT, Claude, Gemini) and input proprietary code, configurations, or credentials, leading to unintended information leakage.
* Log Source Requirements: Proxy logs tracking generative AI service endpoints.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): NO. Monitored at network level.
  - NIDS (Suricata + Zeek): YES. Network connections to GenAI domains.
* Log Sources Covered:
  - Web Proxy & Firewall logs (product: proxy, service: web_server)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
