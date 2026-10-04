import pandas as pd
import json
from datetime import datetime

def generate_soc_feed():
    print("[3/3] Generating SOC Feed...")
    df = pd.read_csv('cleaned_phishing.csv')

    # 1. MISP / SIEM compatible JSON
    ioc_feed = []
    for _, row in df.iterrows():
        ioc_feed.append({
            "type": "url",
            "value": row['url'],
            "threat": row['threat'],
            "brand": row['brand_impersonated'],
            "risk_score": int(row['risk_score']),
            "tld": row['tld'],
            "first_seen": row['timestamp']
        })

    with open('warehouse/ioc_feed.json', 'w') as f:
        json.dump(ioc_feed, f, indent=2)

    # 2. Blocklist for Firewall
    blocklist = df['domain'].unique().tolist()
    with open('warehouse/blocklist.txt', 'w') as f:
        f.write("\n".join(blocklist))

    # 3. Summary for Analyst
    summary = {
        "total_iocs": len(df),
        "top_tld": df['tld'].value_counts().to_dict(),
        "top_brand_impersonated": df['brand_impersonated'].value_counts().to_dict(),
        "avg_risk": df['risk_score'].mean(),
        "generated_at": datetime.now().isoformat()
    }

    df_summary = pd.DataFrame([summary])
    df_summary.to_csv('warehouse/threat_summary.csv', index=False)

    print("✅ SOC Artifacts Generated:")
    print(f" - warehouse/ioc_feed.json ({len(ioc_feed)} IOCs)")
    print(f" - warehouse/blocklist.txt ({len(blocklist)} domains)")
    print(f" - warehouse/threat_summary.csv")

if __name__ == "__main__":
    import os
    os.makedirs('warehouse', exist_ok=True)
    generate_soc_feed()