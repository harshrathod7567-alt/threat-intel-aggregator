import requests

FEED_URL = "https://iplists.firehol.org/files/firehol_level1.netset"

def fetch_feed(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text

def parse_ip_list(raw_text):
    ips = []
    for line in raw_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):  # skip comments/blank lines
            ips.append(line)
    return ips

raw_data = fetch_feed(FEED_URL)
malicious_ips = parse_ip_list(raw_data)

print(f"Fetched {len(malicious_ips)} entries from the threat feed")
print("Sample entries:")
for ip in malicious_ips[:10]:
    print(f"  {ip}")
