#!/bin/bash

# Define variables
PCAP_FILE="dtls_traffic.pcap"
SERVER_CMD="./server-dtls-coap"
TCPDUMP_CMD="tcpdump -i enp0s8 udp port 2444 -w $PCAP_FILE"
SUMMARY_FILE="handshake_summary.txt"

# Function to stop processes and process the pcap file
cleanup() {

    if [[ -n "$TCPDUMP_PID" ]]; then
        kill $TCPDUMP_PID 2>/dev/null
    fi

    exit 0
}

# Trap signals (e.g., Ctrl+C) to run cleanup
trap cleanup SIGINT SIGTERM EXIT

# Start packet capture in the background
echo "Starting packet capture..."
$TCPDUMP_CMD &
TCPDUMP_PID=$!

sleep 0.1

# Start the DTLS server
echo "Starting DTLS server..."
$SERVER_CMD

# Cleanup after server stops
cleanup
