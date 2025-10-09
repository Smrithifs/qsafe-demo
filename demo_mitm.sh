#!/bin/bash
# Q-SAFE MITM Attack Demonstration Script
# Automated demo showing MITM attacks and why they fail

set -e

echo "🛡️  Q-SAFE MITM Attack Demonstration"
echo "===================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check dependencies
echo "📋 Checking dependencies..."
python3 -c "import scapy, flask, flask_socketio" 2>/dev/null || {
    echo "❌ Missing dependencies. Installing..."
    pip install -r requirements.txt
}
echo "✅ Dependencies OK"
echo ""

# Create logs directory
mkdir -p logs

# Clean up any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "satellite/server.py" 2>/dev/null || true
pkill -f "device/device.py" 2>/dev/null || true
pkill -f "mitm_interceptor.py" 2>/dev/null || true
pkill -f "network_visualizer.py" 2>/dev/null || true
sleep 2

# Start topology visualizer
echo "🗺️  Starting network topology visualizer..."
python3 topology/network_visualizer.py &
TOPOLOGY_PID=$!
sleep 3

# Start MITM interceptor
echo "🔴 Starting MITM interceptor..."
python3 mitm_simulator/mitm_interceptor.py --duration 120 --tamper &
MITM_PID=$!
sleep 2

# Start satellite server
echo "🛰️  Starting satellite server..."
python3 satellite/server.py &
SATELLITE_PID=$!
sleep 3

echo ""
echo "🎯 Demo Phase 1: Normal Operation"
echo "================================="

# Start devices
echo "📱 Starting Device A..."
python3 device/device.py A &
DEVICE_A_PID=$!
sleep 2

echo "📱 Starting Device B..."
python3 device/device.py B &
DEVICE_B_PID=$!
sleep 3

# Generate keys
echo "🔐 Generating device keys..."
echo "keygen" | nc localhost 8080 &
echo "keygen" | nc localhost 8081 &
sleep 2

# Send normal messages
echo "📤 Sending encrypted messages..."
for i in {1..3}; do
    echo "💬 Sending message $i..."
    echo "send B Hello from A - Message $i" | nc localhost 8080 &
    sleep 2
done

echo ""
echo "🎯 Demo Phase 2: Satellite Outage & Mesh Fallback"
echo "================================================="

# Simulate satellite outage
echo "🛰️  Simulating satellite outage..."
kill $SATELLITE_PID 2>/dev/null || true
sleep 2

# Send mesh messages
echo "🔗 Sending mesh messages..."
for i in {4..6}; do
    echo "💬 Sending mesh message $i..."
    echo "send B Mesh message $i - satellite down" | nc localhost 8080 &
    sleep 2
done

echo ""
echo "🎯 Demo Phase 3: Attack Simulation"
echo "=================================="

# Restart satellite
echo "🛰️  Restarting satellite..."
python3 satellite/server.py &
SATELLITE_PID=$!
sleep 3

# Simulate various attacks
echo "⚔️  Simulating MITM attacks..."

# Key exfiltration attempt
echo "🔓 Attempting key exfiltration on Device A..."
python3 attack_simulator/key_exfiltration.py A &
sleep 3

# Trigger capture event
echo "🚨 Triggering capture event on Device A..."
python3 attack_simulator/trigger_capture.py A &
sleep 5

# Try to extract keys after capture
echo "🔓 Attempting key extraction after capture..."
python3 attack_simulator/key_exfiltration.py A &
sleep 3

echo ""
echo "🎯 Demo Phase 4: PCAP Generation & Analysis"
echo "==========================================="

# Generate PCAP files
echo "📦 Generating PCAP files..."
python3 pcap_generator/packet_capture.py --sample
python3 pcap_generator/packet_capture.py --duration 10 &
PCAP_PID=$!

# Send final messages for capture
echo "📤 Sending final messages for PCAP capture..."
for i in {7..10}; do
    echo "💬 Final message $i..."
    echo "send B Final encrypted message $i" | nc localhost 8081 &
    sleep 1
done

wait $PCAP_PID

echo ""
echo "🎯 Demo Phase 5: Analysis & Reports"
echo "==================================="

# Wait for MITM interceptor to finish
echo "⏳ Waiting for MITM analysis to complete..."
sleep 10

# Analyze captured packets
echo "🔍 Analyzing captured packets..."
if [ -f "logs/mitm_capture.pcap" ]; then
    python3 wireshark_demo/analyze_qsafe_pcap.py logs/mitm_capture.pcap --commands
fi

if [ -f "logs/qsafe_demo.pcap" ]; then
    python3 wireshark_demo/analyze_qsafe_pcap.py logs/qsafe_demo.pcap
fi

echo ""
echo "📊 Demo Results Summary"
echo "======================"

# Display MITM report
if [ -f "logs/mitm_report.txt" ]; then
    echo "🔴 MITM Attack Report:"
    echo "---------------------"
    cat logs/mitm_report.txt
    echo ""
fi

# Display captured files
echo "📁 Generated Files:"
echo "------------------"
ls -la logs/*.pcap 2>/dev/null || echo "No PCAP files generated"
ls -la logs/*.log 2>/dev/null || echo "No log files generated"
ls -la logs/*.txt 2>/dev/null || echo "No report files generated"
ls -la logs/*.json 2>/dev/null || echo "No metadata files generated"

echo ""
echo "🎯 Judge Instructions"
echo "===================="
echo "1. 🌐 Open network topology: http://localhost:5001"
echo "2. 📊 Open satellite dashboard: http://localhost:5000"
echo "3. 🔍 Analyze PCAP files with Wireshark:"
echo "   wireshark logs/mitm_capture.pcap"
echo "   wireshark logs/qsafe_demo.pcap"
echo "4. 📋 Review attack reports in logs/ directory"
echo "5. ✅ Verify all attacks failed/were detected"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up demo processes..."
    kill $DEVICE_A_PID $DEVICE_B_PID $SATELLITE_PID $MITM_PID $TOPOLOGY_PID 2>/dev/null || true
    echo "✅ Demo cleanup complete"
}

# Set trap for cleanup
trap cleanup EXIT

echo "🎬 Demo complete! Press Ctrl+C to cleanup and exit."
echo "📊 Topology visualizer: http://localhost:5001"
echo "🛰️  Satellite dashboard: http://localhost:5000"

# Keep script running to maintain services
while true; do
    sleep 10
    # Check if key processes are still running
    if ! kill -0 $TOPOLOGY_PID 2>/dev/null; then
        echo "⚠️  Topology visualizer stopped"
        break
    fi
done
