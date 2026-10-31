#!/bin/sh
# Look at this host the way the Electrosphere sees it, with keyless endpoints only.
# Usage: ./external-vantage.sh
set -u

ip=$(curl -qs --max-time 10 https://api.ipify.org) || { echo 'no egress'; exit 1; }
printf 'public ip: %s\n\n' "$ip"

printf 'tor check:         '; curl -qs --max-time 10 "https://check.torproject.org/api/ip"; echo

printf 'onionoo relays:    '
curl -qs --max-time 15 "https://onionoo.torproject.org/details?search=$ip" |
	python3 -c 'import sys,json;r=json.load(sys.stdin).get("relays") or [];print(len(r),[x.get("nickname") for x in r][:3])' 2>/dev/null ||
	echo 'query failed'

printf 'shodan internetdb: '; curl -qs --max-time 10 "https://internetdb.shodan.io/$ip"; echo

printf 'rdap network:      '
curl -qsL --max-time 12 "https://rdap.org/ip/$ip" -o /tmp/.rdap.$$ 2>/dev/null
python3 - /tmp/.rdap.$$ <<'PYEOF'
import sys, json
try:
	d = json.load(open(sys.argv[1]))
except Exception:
	print("(non-JSON or empty response)")
	sys.exit(0)
print(d.get("handle"), d.get("name"), d.get("startAddress"), d.get("endAddress"))
PYEOF
rm -f /tmp/.rdap.$$
