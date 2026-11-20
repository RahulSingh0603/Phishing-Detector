import os
import sys
import subprocess
import bz2
import pandas as pd

DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(DATASET_DIR, "urls.csv")
PHISHTANK_BZ2 = os.path.join(DATASET_DIR, "phishtank.csv.bz2")
TOP_LEGIT_FILE = os.path.join(DATASET_DIR, "top10k_legit.txt")
OPENPHISH_FILE = os.path.join(DATASET_DIR, "live_openphish.txt")

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv.bz2"
OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
TOP_DOMAINS_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-10000-domains"

def update_realtime_dataset(target_sample_size=10000):
    print("=" * 65)
    print(" [PhishGuard AI] Live Real-Time Dataset Collector & Builder")
    print("=" * 65)

    # 1. Ensure PhishTank live database is downloaded
    if not os.path.exists(PHISHTANK_BZ2) or os.path.getsize(PHISHTANK_BZ2) < 50000:
        print("Downloading latest verified PhishTank database...")
        cmd = f'curl -s -L -A "phishtank/rohan-project" "{PHISHTANK_URL}" -o "{PHISHTANK_BZ2}"'
        subprocess.run(cmd, shell=True, check=True)
        print("PhishTank database download completed.")

    print("Loading verified PhishTank dataset...")
    df_phish = pd.read_csv(PHISHTANK_BZ2, compression='bz2', on_bad_lines='skip')
    print(f"Loaded {len(df_phish)} verified live phishing records from PhishTank.")

    # 2. Collect OpenPhish zero-day live feed
    live_openphish = []
    print("\nFetching latest live active phishing feeds from OpenPhish...")
    try:
        cmd = f'curl -s -L "{OPENPHISH_FEED_URL}" -o "{OPENPHISH_FILE}"'
        subprocess.run(cmd, shell=True)
        if os.path.exists(OPENPHISH_FILE):
            with open(OPENPHISH_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    u = line.strip()
                    if u.startswith("http"):
                        live_openphish.append(u)
        print(f"Collected {len(live_openphish)} zero-day active URLs from OpenPhish.")
    except Exception as e:
        print(f"OpenPhish collection note: {e}")

    # 3. Fetch top legitimate domain database
    if not os.path.exists(TOP_LEGIT_FILE) or os.path.getsize(TOP_LEGIT_FILE) < 5000:
        print("\nDownloading top legitimate domains list...")
        cmd = f'curl -s -L "{TOP_DOMAINS_URL}" -o "{TOP_LEGIT_FILE}"'
        subprocess.run(cmd, shell=True)

    legit_domains = []
    if os.path.exists(TOP_LEGIT_FILE):
        with open(TOP_LEGIT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    legit_domains.append(d)

    print(f"Loaded {len(legit_domains)} real-world verified legitimate domains.")

    # 4. Synthesize balanced real-time dataset
    samples_per_class = target_sample_size // 2

    # Phishing collection
    phishing_set = set(live_openphish)
    # Add verified PhishTank URLs
    for u in df_phish['url'].dropna():
        phishing_set.add(str(u).strip())
        if len(phishing_set) >= samples_per_class:
            break

    phishing_list = list(phishing_set)[:samples_per_class]

    # Legitimate collection
    legit_urls = []
    # Mix HTTPS and HTTP, www and bare domain, plus common paths to mirror realistic browsing
    common_subpaths = ["", "/", "/login", "/search", "/about", "/help", "/contact", "/dashboard", "/explore"]
    for i, d in enumerate(legit_domains[:samples_per_class]):
        protocol = "https://" if i % 10 != 0 else "http://"
        prefix = "www." if i % 2 == 0 else ""
        sub = common_subpaths[i % len(common_subpaths)]
        legit_urls.append(f"{protocol}{prefix}{d}{sub}")

    min_samples = min(len(phishing_list), len(legit_urls))
    phishing_list = phishing_list[:min_samples]
    legit_urls = legit_urls[:min_samples]

    data = []
    for u in legit_urls:
        data.append({'url': u, 'label': 0})
    for u in phishing_list:
        data.append({'url': u, 'label': 1})

    df_final = pd.DataFrame(data)
    # Shuffle randomly
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

    df_final.to_csv(OUTPUT_FILE, index=False)
    print("\n" + "=" * 65)
    print(f"[SUCCESS] Real-World Dataset built successfully: {OUTPUT_FILE}")
    print(f"Total samples: {len(df_final)} | Legitimate (0): {min_samples} | Phishing (1): {min_samples}")
    print("=" * 65)
    return True

if __name__ == "__main__":
    update_realtime_dataset(target_sample_size=10000)
