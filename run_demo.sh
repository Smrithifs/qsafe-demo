#!/bin/bash

# Q-SAFE Demo Runner
# Automated demonstration of secure soldier communications

set -e

echo "🛰️  Q-SAFE Secure Communications Demo"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Python dependencies are installed
echo -e "${BLUE}Checking dependencies...${NC}"
if ! python3 -c "import flask, socketio, colorama, pytest" 2>/dev/null; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
fi

# Create logs directory
mkdir -p logs

# Function to cleanup background processes
cleanup() {
    echo -e "\n${YELLOW}Cleaning up processes...${NC}"
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${GREEN}✅ Dependencies ready${NC}"
echo ""

# Start satellite server
echo -e "${BLUE}🛰️  Starting satellite server...${NC}"
python3 satellite/server.py > logs/satellite.log 2>&1 &
SATELLITE_PID=$!
sleep 3

# Check if satellite started successfully
if ! curl -s http://localhost:5000/api/status > /dev/null; then
    echo -e "${RED}❌ Failed to start satellite server${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Satellite server running (PID: $SATELLITE_PID)${NC}"

# Start Device A
echo -e "${BLUE}📱 Starting Device A...${NC}"
python3 device/device.py --id A > logs/device_a.log 2>&1 &
DEVICE_A_PID=$!
sleep 2
echo -e "${GREEN}✅ Device A running (PID: $DEVICE_A_PID)${NC}"

# Start Device B  
echo -e "${BLUE}📱 Starting Device B...${NC}"
python3 device/device.py --id B > logs/device_b.log 2>&1 &
DEVICE_B_PID=$!
sleep 2
echo -e "${GREEN}✅ Device B running (PID: $DEVICE_B_PID)${NC}"

echo ""
echo -e "${GREEN}🚀 All systems operational!${NC}"
echo -e "${BLUE}📊 Dashboard: http://localhost:5000${NC}"
echo ""

# Demo Scenario 1: Normal Operation
echo -e "${GREEN}=== DEMO SCENARIO 1: Normal Operation ===${NC}"
echo -e "${BLUE}📤 Device A sending message to Device B via satellite...${NC}"
python3 device/device.py --id A --auto-send B --message "Hello Device B! This is a secure message via satellite." &
sleep 3
echo -e "${GREEN}✅ Normal operation complete${NC}"
echo ""

# Demo Scenario 2: Satellite Outage (Mesh Fallback)
echo -e "${YELLOW}=== DEMO SCENARIO 2: Satellite Outage ===${NC}"
echo -e "${YELLOW}📡 Simulating satellite outage...${NC}"
curl -s -X POST http://localhost:5000/api/toggle > /dev/null
sleep 1

echo -e "${YELLOW}📤 Device A attempting to send message (should fallback to mesh)...${NC}"
python3 device/device.py --id A --auto-send B --message "Emergency message via mesh backup!" &
sleep 3

echo -e "${BLUE}📡 Restoring satellite...${NC}"
curl -s -X POST http://localhost:5000/api/toggle > /dev/null
echo -e "${GREEN}✅ Mesh fallback demonstration complete${NC}"
echo ""

# Demo Scenario 3: Attack Simulation
echo -e "${RED}=== DEMO SCENARIO 3: Attack Simulation ===${NC}"
echo -e "${RED}🚨 Running MITM attack simulation...${NC}"
python3 attack_simulator/mitm_attack.py --attack mitm
sleep 2

echo -e "${RED}🔄 Running replay attack simulation...${NC}"
python3 attack_simulator/mitm_attack.py --attack replay
sleep 2
echo -e "${GREEN}✅ Attack simulations complete (all should be detected/prevented)${NC}"
echo ""

# Demo Scenario 4: Device Capture & Self-Destruct
echo -e "${RED}=== DEMO SCENARIO 4: Device Capture ===${NC}"
echo -e "${RED}🚨 Simulating Device B capture...${NC}"
python3 attack_simulator/trigger_capture.py --target B
sleep 3

echo -e "${RED}🔓 Attempting key exfiltration from captured device...${NC}"
python3 attack_simulator/key_exfiltration.py --target B
echo -e "${GREEN}✅ Self-destruct demonstration complete${NC}"
echo ""

# Run tests
echo -e "${BLUE}=== RUNNING SECURITY TESTS ===${NC}"
echo -e "${BLUE}🧪 Running crypto tests...${NC}"
python3 -m pytest tests/test_crypto.py -v --tb=short
echo ""

echo -e "${BLUE}🧪 Running device tests...${NC}"
python3 -m pytest tests/test_device.py -v --tb=short
echo ""

# Generate demo report
echo -e "${BLUE}📋 Generating demo report...${NC}"
./generate_demo_report.sh

echo ""
echo -e "${GREEN}🎉 Q-SAFE DEMO COMPLETE! 🎉${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${BLUE}📊 Dashboard: http://localhost:5000${NC}"
echo -e "${BLUE}📋 Demo report: logs/demo_report.txt${NC}"
echo -e "${BLUE}📁 Logs directory: logs/${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"

# Keep services running
wait
