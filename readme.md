# Phishing Intelligence Pipeline — SOC Threat Intel Feed

Automated ETL that fetches live phishing URLs, enriches IOCs, and generates SIEM-ready feeds for SOC teams.

## Pipeline
`scraper.py` (OpenPhish/URLHaus) → `etl.py` (tldextract + enrichment) → `analyzer.py` (MISP JSON + blocklist) → `warehouse/`

## Outputs for SOC
- `warehouse/ioc_feed.json` — MISP/SIEM compatible
- `warehouse/blocklist.txt` — Firewall/Proxy blocklist
- `warehouse/threat_summary.csv` — Analyst dashboard

## Tech
Pandas, tldextract, Threat Intel enrichment

## Run
`pip install -r requirements.txt && python main.py`

---
## 🔗 Part of Nigeria Intelligence Empire
[1. Abuja Price Intelligence](https://github.com/mrrmoh/abuja-price-intelligence) | [2. Fuel Intelligence](https://github.com/mrrmoh/nigeria-fuel-intelligence) | [3. Rent Intelligence](https://github.com/mrrmoh/abuja-rent-intelligence) | [4. This Repo] | [5. Master Connector (coming)]