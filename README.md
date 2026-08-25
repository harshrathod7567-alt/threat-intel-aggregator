# Threat Intel Feed Aggregator

A beginner Python project that fetches a live public threat intelligence feed 
(FireHOL's IP blocklist), then cross-references IPs extracted from a log file 
against it — automating the "logs → threat intel → flagged report" workflow 
used in real SOC triage.

## What it does
- Fetches a live, regularly-updated threat feed (no API key required)
- Parses both single IPs and CIDR ranges using Python's `ipaddress` module
- Extracts unique IPs from a log file automatically
- Cross-references each IP against the threat feed
- Saves a report flagging any matches

## Files
- `threat_aggregator.py` — the main script
- `sample.log` — example log file to scan for IPs (reused from the log analyzer project)

## Setup
Install dependencies: `pip install requests`

## How to run it
1. Make sure `sample.log` is in the same folder
2. Run: `python threat_aggregator.py`
3. Check the terminal output and `threat_report.txt` for results

## Example output

Loaded 4200+ network ranges from threat feed
Found 4 unique IPs in the log file

10.0.0.5: ⚠️ MATCHED: 10.0.0.0/8
192.168.1.15: clean
8.8.8.8: clean
192.168.1.10: clean


## What I learned
- Working with Python's `ipaddress` module for CIDR range matching (not just exact string matching)
- Fetching and parsing live external threat intelligence feeds
- Chaining tools together into a pipeline (logs → extraction → lookup → report), 
  similar to real SOC automation workflows
- That sandboxed/restricted network environments can block outbound requests to 
  external feeds — a real consideration when deploying tools in locked-down 
  corporate environments too

## Next steps
- Support multiple feeds at once (URLhaus for malicious URLs, abuse.ch for malware hashes)
- Cache the feed locally and only refresh it periodically (avoid re-downloading every run)
- Add domain reputation checking, not just IPs
