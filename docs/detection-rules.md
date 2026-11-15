# Detection rules

| Rule ID | Detection | ATT&CK | Severity |
|---|---|---|---|
| AUTH-PASSWORD-SPRAY | One source fails against multiple distinct usernames within 10 minutes | T1110.003 | High |
| AUTH-DISTRIBUTED-BRUTE | One username receives failures from multiple source IPs within 10 minutes | T1110 | High |

Thresholds are initial heuristics, not universal truth. Validate against representative benign and malicious fixtures. Risk scores are triage hints, not probabilities.
