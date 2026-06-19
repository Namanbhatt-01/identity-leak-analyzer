#!/bin/bash

# ANSI Color Codes
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RESET='\033[0m'

echo -e "${BLUE}[+] STEP 1: Configuring and Rebuilding Library and Binaries${RESET}"
sleep 1
cmake -B build -S .
cmake --build build

echo ""
echo -e "${BLUE}[+] STEP 2: Executing Batch Scan with Rate Limiting and Tor Proxy Telemetry${RESET}"
sleep 1.5
./build/identity_leak_analyzer --credentials config.json --tor-proxy 127.0.0.1:9050 --output report.json

echo ""
echo -e "${BLUE}[+] STEP 3: Verifying Defensive Input Validation (Simulated Injection)${RESET}"
sleep 1.5
./build/identity_leak_analyzer --target "malicious_user; rm -rf"

echo ""
echo -e "${GREEN}[+] Demonstration Complete!${RESET}"
sleep 1
