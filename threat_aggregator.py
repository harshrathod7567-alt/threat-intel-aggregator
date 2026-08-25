import requests
import ipaddress

FEED_URL = "https://iplists.firehol.org/files/firehol_level1.netset"

def fetch_feed(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text

def parse_ip_list(raw_text):
    entries = []
    for line in raw_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                # handles both single IPs and CIDR ranges (e.g. 10.0.0.0/8)
                entries.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue  # skip malformed lines
    return entries

def check_ip_against_feed(ip_str, feed_entries):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, None
    
    for network in feed_entries:
        if ip_obj in network:
            return True, str(network)
    
    return False, None

raw_data = fetch_feed(FEED_URL)
feed_entries = parse_ip_list(raw_data)

print(f"Loaded {len(feed_entries)} network ranges from threat feed\n")

# test a few IPs
test_ips = ["8.8.8.8", "1.1.1.1", "10.0.0.5"]

for ip in test_ips:
    is_malicious, matched_range = check_ip_against_feed(ip, feed_entries)
    if is_malicious:
        print(f"⚠️ {ip} — MATCHED malicious range: {matched_range}")
    else:
        print(f"{ip} — not found in threat feed")
