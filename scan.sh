#!/bin/bash

# set vars
id="$1"
ppath="$(pwd)"
scope_path="$ppath/scope/$id"

timestamp="$(date +%s)"
scan_path="$ppath/scans/$id-$timestamp"

# exit if scope path doesnt exist
if [ ! -d "$scope_path" ]; then
    echo "Path doesn't exist"
    exit 1
fi

mkdir -p "$scan_path"
cd "$scan_path"


### PERFORM SCAN ###

# SETUP
echo "Starting scan against roots:"
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"
sleep 3

# DNS Enumeration - Find Subdomains
cat "$scan_path/roots.txt" | subfinder | anew subs.txt

shuffledns -l  "$scan_path/roots.txt"  -w "$ppath/lists/subdomains.txt" -r "$ppath/lists/resolvers.txt" -mode bruteforce | anew subs.txt


# DNS Resolution - Resolve Discoverd Subdomains
puredns resolve "$scan_path/subs.txt" -r "$ppath/lists/resolvers.txt" -w "$scan_path/resolved.txt" | wc -l 
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json" | jq -r '.a?[]?' | anew "$scan_path/ips.txt"  | wc -l 


# Port Scanning & HTTP Server Discovery
nmap -T4 -vv -iL "$scan_path/ips.txt" --top-ports 3000 -n --open -oX "$scan_path/nmap.xml"
tew -x "$scan_path/nmap.xml" -dnsx "$scan_path/dns.json" --vhost -o "$scan_path/hostport.txt" | httpx -sr -srd "$scan_path/response" -json -o "$scan_path/http.json"

cat "$scan_path/http.json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u > "$scan_path/http.txt"


# Crawling
gospider -S "$scan_path/http.txt" --json | grep "{" | jq -r '.output?' | tee "$scan_path/crawl.txt"


# Javascript Pulling
cat "$scan_path/crawl.txt" | grep "\.js" | httpx -sr -srd js



################# ADD SCAN LOGIC HERE #################

# calculate time diff
end_time=$(date +%s)
seconds="$((end_time - timestamp))"
time=""

if [[ "$seconds" -gt 59 ]]
then 
    minutes=$(( seconds / 60))
    time="$minutes minutes"
else 
    time="$seconds seconds"

fi 

echo "Scan $id took $time"