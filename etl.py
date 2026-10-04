import pandas as pd
from urllib.parse import urlparse

def clean_iocs():
    print("[2/3] Cleaning & Enriching IOCs...")
    df = pd.read_csv('raw_phishing.csv')

    def extract_features(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            tld = domain.split('.')[-1] if '.' in domain else ''
            return {
                'domain': domain,
                'tld': tld,
                'is_ip': parsed.netloc.replace('.','').isdigit(),
                'url_length': len(url),
                'num_dots': url.count('.'),
                'has_at_symbol': '@' in url
            }
        except:
            return {'domain':'unknown','tld':'unknown','is_ip':False,'url_length':0,'num_dots':0,'has_at_symbol':False}

    features = df['url'].apply(extract_features).apply(pd.Series)
    df = pd.concat([df, features], axis=1)

    def get_brand(x):
        x = x.lower()
        if 'facebook' in x: return 'Facebook'
        if 'microsoft' in x: return 'Microsoft'
        if 'gtbank' in x: return 'GTBank'
        if 'dhl' in x: return 'DHL'
        return 'Generic'

    df['brand_impersonated'] = df['url'].apply(get_brand)
    df['risk_score'] = df['tld'].apply(lambda x: 90 if x in ['tk','ml','ga','cf','gq'] else 60)

    df.to_csv('cleaned_phishing.csv', index=False)
    print(f"✅ Cleaned {len(df)} IOCs")
    return df