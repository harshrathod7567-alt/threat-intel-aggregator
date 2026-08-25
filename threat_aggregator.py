import requests
import ipaddress
import re

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
                entries.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
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

def extract_ips_from_log(filename):
    ips = set()
    ip_pattern = r'ip=(\d+\.\d+\.\d+\.\d+)'
    with open(filename, 'r') as f:
        for line in f:
            match = re.search(ip_pattern, line)
            if match:
                ips.add(match.group(1))
    return list(ips)

def write_report(results, output_file="threat_report.txt"):
    with open(output_file, 'w') as f:
        f.write("=== Threat Intel Aggregator Report ===\n\n")
        for ip, is_malicious, matched_range in results:
            if is_malicious:
                f.write(f"⚠️ {ip} — MATCHED malicious range: {matched_range}\n")
            else:
                f.write(f"{ip} — clean, not found in threat feed\n")
    print(f"Report saved to {output_file}")

raw_data = fetch_feed(FEED_URL)
feed_entries = parse_ip_list(raw_data)
print(f"Loaded {len(feed_entries)} network ranges from threat feed\n")

log_ips = extract_ips_from_log("sample.log")  # reuse a log file from project 1
print(f"Found {len(log_ips)} unique IPs in the log file\n")

results = []
for ip in log_ips:
    is_malicious, matched_range = check_ip_against_feed(ip, feed_entries)
    results.append((ip, is_malicious, matched_range))
    status = f"⚠️ MATCHED: {matched_range}" if is_malicious else "clean"
    print(f"{ip}: {status}")

write_report(results)
