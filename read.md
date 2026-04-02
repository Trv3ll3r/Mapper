Install

pip install scapy requests dnspython colorama


Usage

# Full scan with diagram
python networkmapper.py https://example.com --mermaid --mermaid-file map.mmd

# Save all results
python networkmapper.py https://example.com -o results.json --mermaid-file map.mmd

# No traceroute, just WAF + port scan
python networkmapper.py https://example.com --no-traceroute --port-scan
