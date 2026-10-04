import requests
import pandas as pd
from datetime import datetime

def fetch_phishing_feed():
    """
    Simulates fetching from OpenPhish / URLHaus / PhishTank
    Using public sample for demo - in prod replace with API
    """
    print("[1/3] Fetching phishing IOC feed...")

    # Using URLHaus recent payload as free source
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        df = pd.read_csv(url, comment='#', header=None)
        df = df[[1,2,5]].copy()
        df.columns = ['timestamp', 'url', 'threat']
        df = df.head(200) # limit for portfolio
    except:
        # Fallback mock data if API down - so your project never breaks
        print("API down, using fallback mock feed (for demo)")
        data = {
            'timestamp': [datetime.now().isoformat()]*10,
            'url': [
                'http://secure-login-facebook-verify.tk/login',
                'http://nigeria-bank-verification.ml/auth',
                'http://dhl-delivery-track-id.ga/track',
                'http://microsoft-365-login-verify.cf/owa',
                'http://whatsapp-verification-code.tk/verify',
                'http://binance-secure-wallet.ml/login',
                'http://usps-tracking-update.ga/us',
                'http://apple-id-locked.cf/unlock',
                'http://gtbank-online-update.ml/login',
                'http://paypal-limited-account.tk/resolve'
            ],
            'threat': ['phishing']*10
        }
        df = pd.DataFrame(data)

    df.to_csv('raw_phishing.csv', index=False)
    print(f"✅ Saved {len(df)} IOCs to raw_phishing.csv")
    return df