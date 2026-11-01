#!/bin/sh
# Look at this host the way the Electrosphere sees it, with keyless endpoints only.
#
# What these answers mean (D39-D43):
#   - Tor / Onionoo: authoritative for Tor *exits* on the address families the list
#     covers. The bulk exit list is IPv4-only, so an IPv6-only exit is unlisted.
#   - Shodan InternetDB / RDAP / CT / passive DNS: these describe an *exposed service*
#     or an address allocation. They say nothing about a host that only dials out.
#   - A clean result here is not a clean host. A CDN-fronted relay and a seedbox on a
#     provider that does not care produce no listing at all.
#
# Usage: ./external-vantage.sh [domain]
set -u
LC_ALL=C
export LC_ALL

domain=${1:-}
tmp=$(mktemp 2>/dev/null) || exit 1
trap 'rm -f "$tmp"' EXIT INT TERM

v4=$(curl -qs -4 --max-time 10 https://api.ipify.org 2>/dev/null)
v6=$(curl -qs -6 --max-time 10 https://api64.ipify.org 2>/dev/null)
case $v6 in *:*) ;; *) v6='' ;; esac

printf 'public ipv4: %s\n' "${v4:-none}"
printf 'public ipv6: %s\n\n' "${v6:-none}"
[ -z "$v4$v6" ] && { echo 'no egress address found'; exit 1; }

printf 'tor check (ipv4):  '
curl -qs --max-time 10 "https://check.torproject.org/api/ip" 2>/dev/null || echo 'query failed'
echo

for ip in $v4 $v6; do
	printf 'onionoo %-39s ' "$ip"
	curl -qs --max-time 15 "https://onionoo.torproject.org/details?search=$ip" 2>/dev/null |
		python3 -c 'import sys,json
try: r=json.load(sys.stdin).get("relays") or []
except Exception: print("query failed"); raise SystemExit
print(len(r), [x.get("nickname") for x in r][:3])' 2>/dev/null || echo 'query failed'
done
printf '   note: a decommissioned exit lingers in exit_addresses for ~24h; a\n'
printf '   short-lived exit is unlisted for most of its life.\n\n'

for ip in $v4 $v6; do
	printf 'shodan %-40s ' "$ip"
	curl -qs --max-time 10 "https://internetdb.shodan.io/$ip" 2>/dev/null || echo 'query failed'
	echo
done
printf '   note: this is a port index. A dial-out-only relay publishes no port.\n\n'

printf 'rdap / abuse contact:\n'
for ip in $v4 $v6; do
	curl -qsL --max-time 12 "https://rdap.org/ip/$ip" -o "$tmp" 2>/dev/null
	python3 - "$tmp" "$ip" <<'PYEOF'
import sys, json
path, ip = sys.argv[1], sys.argv[2]
try:
	d = json.load(open(path))
except Exception:
	print(f"  {ip}: non-JSON or empty response")
	raise SystemExit(0)
print(f"  {ip}: {d.get('handle')} {d.get('name')} {d.get('startAddress')}-{d.get('endAddress')}")
found = False
def walk(ents):
	global found
	for e in ents or []:
		roles = e.get("roles") or []
		if "abuse" in roles:
			for item in (e.get("vcardArray") or [None, []])[1]:
				if item and item[0] in ("fn", "email"):
					print(f"    abuse {item[0]}: {item[3]}")
					found = True
		walk(e.get("entities"))
walk(d.get("entities"))
if not found:
	print("    NO abuse-c in this object: a complaint sent here has no destination.")
	print("    fallback: whois -h whois.iana.org <ip>, then the RIR's own whois, then PeeringDB.")
PYEOF
done

if [ -n "$domain" ]; then
	printf '\ncertificate transparency for %s (last 5 names):\n' "$domain"
	curl -qs --max-time 20 "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null |
		python3 -c 'import sys,json
try: rows=json.load(sys.stdin)
except Exception: print("  query failed"); raise SystemExit
names=sorted({n for r in rows for n in (r.get("name_value") or "").split("\n") if n})
print("  " + ", ".join(names[:5]) if names else "  none")' 2>/dev/null
	printf '   note: a service behind Cloudflare universal TLS is logged under Cloudflare.\n'
fi

printf '\nWhat this does not answer: whether this host is a relay. A CDN-fronted tunnel,\n'
printf 'a SOCKS pool and a private seedbox have no listing anywhere above. See\n'
printf 'HARDENING.md, D39-D43.\n'
exit 0