#!/bin/bash

# Function to stop processes and process the pcap file
cleanup() {
    if [[ -n "$TCPDUMP_PID" ]] && ps -p $TCPDUMP_PID > /dev/null 2>&1; then
        echo "Stopping tcpdump..."
        kill $TCPDUMP_PID 2>/dev/null
        wait $TCPDUMP_PID 2>/dev/null || true  # Ensure tcpdump has fully stopped
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT
# Start packet capture in the background
tcpdump -i enp0s8 udp port 2444 -w dtls_traffic.pcap &
TCPDUMP_PID=$!
sleep 0.1
./server-dtls-coap
sleep 1

cleanup
