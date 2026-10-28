# Risk Model

Finding scores are deterministic and bounded to 0–100. CVSS v3/v4 base score is multiplied by ten; web findings without CVSS use the documented severity anchors: Critical 95, High 80, Medium 55, Low 30, Info 5. EPSS adds up to 12 points, CISA KEV adds 15, internet exposure adds 8, transitive dependencies subtract 5, and a known fix adds 2. Confidence scales the result: high 1.0, medium 0.85, low 0.65. The final score is clamped to 0–100.

Bands are Critical ≥85, High ≥65, Medium ≥40, Low ≥15, and Info <15. Scan aggregation is the highest finding score plus 12% of each remaining score, capped at 100; this prevents a serious finding being averaged away. False-positive findings are excluded when recalculating scan risk.

The current feed integration consumes OSV advisory severity and fixed-version data. EPSS, KEV, internet-exposure overrides, threshold configuration, and scan-to-scan trends are not yet populated from external sources; those modifiers are supported by the scoring function where supplied but are not claimed as automated coverage.
