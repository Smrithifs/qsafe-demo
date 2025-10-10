#!/usr/bin/env python3
"""
Q-SAFE Network Topology Visualizer
Live visualization of message routes and attack attempts
"""

import json
import time
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qsafe-topology'
socketio = SocketIO(app, cors_allowed_origins="*")

# Network topology state
topology_state = {
    'nodes': {
        'DEVICE_A': {'x': 100, 'y': 200, 'status': 'offline', 'type': 'device'},
        'SATELLITE': {'x': 300, 'y': 100, 'status': 'online', 'type': 'satellite'},
        'DEVICE_B': {'x': 500, 'y': 200, 'status': 'offline', 'type': 'device'},
        'ATTACKER': {'x': 300, 'y': 300, 'status': 'active', 'type': 'attacker'}
    },
    'messages': [],
    'attacks': []
}

TOPOLOGY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-SAFE Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { margin: 0; padding: 20px; background: #000; color: #0f0; font-family: monospace; }
        .topology-container { width: 100%; height: 600px; border: 1px solid #0f0; background: #111; }
        .controls { margin: 20px 0; }
        .controls button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 10px; margin: 5px; }
        .legend { margin: 20px 0; }
        .legend-item { display: inline-block; margin: 10px; }
        .node { cursor: pointer; }
        .device { fill: #0f0; }
        .satellite { fill: #00f; }
        .attacker { fill: #f00; }
        .offline { opacity: 0.5; }
        .message-path { stroke-width: 3; fill: none; }
        .secure { stroke: #0f0; }
        .mesh { stroke: #ff0; }
        .intercepted { stroke: #f00; stroke-dasharray: 5,5; }
        .tooltip { position: absolute; background: #333; color: #0f0; padding: 10px; border: 1px solid #0f0; display: none; z-index: 1000; }
    </style>
</head>
<body>
    <h1>🛰️ Q-SAFE Network Topology</h1>
    
    <div class="controls">
        <button onclick="clearMessages()">Clear Messages</button>
        <button onclick="toggleAttacker()">Toggle Attacker</button>
        <button onclick="exportTopology()">Export Topology</button>
    </div>
    
    <div class="legend">
        <div class="legend-item">🟢 <strong>Secure Route:</strong> Satellite relay</div>
        <div class="legend-item">🟡 <strong>Mesh Route:</strong> Peer-to-peer</div>
        <div class="legend-item">🔴 <strong>Intercepted:</strong> MITM attack</div>
    </div>
    
    <div class="topology-container" id="topology"></div>
    
    <div class="tooltip" id="tooltip"></div>
    
    <div id="message-log" style="height: 200px; overflow-y: scroll; border: 1px solid #333; padding: 10px; margin-top: 20px;">
        <h3>Message Log</h3>
        <div id="log-entries"></div>
    </div>

    <script>
        const socket = io();
        let svg, nodes, links;
        const width = 800, height = 600;
        
        // Initialize D3 visualization
        function initTopology() {
            svg = d3.select("#topology")
                .append("svg")
                .attr("width", width)
                .attr("height", height);
            
            // Create groups for different elements
            svg.append("g").attr("id", "links");
            svg.append("g").attr("id", "nodes");
            svg.append("g").attr("id", "labels");
            
            updateTopology();
        }
        
        function updateTopology() {
            const nodeData = Object.entries(topologyData.nodes).map(([id, data]) => ({
                id: id,
                x: data.x,
                y: data.y,
                status: data.status,
                type: data.type
            }));
            
            // Update nodes
            const nodeSelection = svg.select("#nodes")
                .selectAll(".node")
                .data(nodeData, d => d.id);
            
            const nodeEnter = nodeSelection.enter()
                .append("g")
                .attr("class", "node")
                .attr("transform", d => `translate(${d.x}, ${d.y})`);
            
            nodeEnter.append("circle")
                .attr("r", 30)
                .attr("class", d => `${d.type} ${d.status}`)
                .on("mouseover", showTooltip)
                .on("mouseout", hideTooltip);
            
            nodeEnter.append("text")
                .attr("text-anchor", "middle")
                .attr("dy", 5)
                .style("fill", "#fff")
                .style("font-size", "10px")
                .text(d => d.id.replace('DEVICE_', ''));
            
            nodeSelection.merge(nodeEnter)
                .select("circle")
                .attr("class", d => `${d.type} ${d.status}`);
        }
        
        function animateMessage(message) {
            console.log("Animating message:", message);
            const fromNode = topologyData.nodes[message.from];
            const toNode = topologyData.nodes[message.to];
            
            if (!fromNode || !toNode) {
                console.log("Missing nodes:", message.from, message.to);
                return;
            }
            
            console.log("From:", fromNode, "To:", toNode);
            
            // Create animated line
            const line = svg.select("#links")
                .append("line")
                .attr("class", `message-path ${message.route_type}`)
                .attr("x1", fromNode.x)
                .attr("y1", fromNode.y)
                .attr("x2", fromNode.x)
                .attr("y2", fromNode.y)
                .style("stroke-width", "4px")
                .style("opacity", 0.8);
            
            console.log("Created line element");
            
            // Animate to destination
            line.transition()
                .duration(3000)
                .attr("x2", toNode.x)
                .attr("y2", toNode.y)
                .on("end", function() {
                    console.log("Animation complete");
                    // Remove line after animation
                    setTimeout(() => {
                        d3.select(this).remove();
                    }, 2000);
                });
            
            // Add message to log
            addMessageToLog(message);
        }
        
        function addMessageToLog(message) {
            const logEntries = document.getElementById('log-entries');
            const entry = document.createElement('div');
            entry.style.color = message.route_type === 'secure' ? '#0f0' : 
                               message.route_type === 'mesh' ? '#ff0' : '#f00';
            entry.innerHTML = `
                [${new Date(message.timestamp * 1000).toLocaleTimeString()}] 
                ${message.from} → ${message.to} 
                (${message.route_type.toUpperCase()}) 
                MSG_ID: ${message.msg_id}
                ${message.pcap_ref ? `| PCAP: ${message.pcap_ref}` : ''}
            `;
            logEntries.appendChild(entry);
            logEntries.scrollTop = logEntries.scrollHeight;
        }
        
        function showTooltip(event, d) {
            const tooltip = document.getElementById('tooltip');
            tooltip.style.display = 'block';
            tooltip.style.left = (event.pageX + 10) + 'px';
            tooltip.style.top = (event.pageY + 10) + 'px';
            tooltip.innerHTML = `
                <strong>${d.id}</strong><br>
                Type: ${d.type}<br>
                Status: ${d.status}<br>
                Position: (${d.x}, ${d.y})
            `;
        }
        
        function hideTooltip() {
            document.getElementById('tooltip').style.display = 'none';
        }
        
        // Socket events
        socket.on('topology_update', function(data) {
            topologyData = data;
            updateTopology();
        });
        
        socket.on('message_event', function(message) {
            animateMessage(message);
        });
        
        socket.on('attack_event', function(attack) {
            // Highlight attacker node
            svg.select("#nodes")
                .selectAll(".attacker")
                .transition()
                .duration(500)
                .attr("r", 40)
                .transition()
                .duration(500)
                .attr("r", 30);
            
            addMessageToLog({
                from: 'ATTACKER',
                to: attack.target,
                route_type: 'intercepted',
                msg_id: attack.attack_type,
                timestamp: attack.timestamp
            });
        });
        
        // Control functions
        function clearMessages() {
            svg.select("#links").selectAll("*").remove();
            document.getElementById('log-entries').innerHTML = '';
        }
        
        function toggleAttacker() {
            const attacker = topologyData.nodes.ATTACKER;
            attacker.status = attacker.status === 'active' ? 'inactive' : 'active';
            updateTopology();
        }
        
        function exportTopology() {
            const data = {
                topology: topologyData,
                messages: Array.from(document.getElementById('log-entries').children).map(el => el.textContent),
                timestamp: new Date().toISOString()
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'qsafe_topology_export.json';
            a.click();
        }
        
        // Initialize
        let topologyData = {{ topology_data | tojson }};
        initTopology();
    </script>
</body>
</html>
"""

@app.route('/')
def topology_view():
    return render_template_string(TOPOLOGY_HTML, topology_data=topology_state)

@app.route('/api/topology/events', methods=['POST'])
def receive_topology_event():
    """Receive events from Q-SAFE system"""
    data = request.json
    event_type = data.get('type')
    
    if event_type == 'message':
        message_event = {
            'msg_id': data.get('msg_id'),
            'from': data.get('from'),
            'to': data.get('to'),
            'route_type': data.get('route_type', 'secure'),
            'timestamp': time.time(),
            'pcap_ref': data.get('pcap_ref'),
            'ciphertext_hex': data.get('ciphertext_hex')
        }
        
        topology_state['messages'].append(message_event)
        socketio.emit('message_event', message_event)
        
    elif event_type == 'attack':
        attack_event = {
            'attack_type': data.get('attack_type'),
            'target': data.get('target'),
            'timestamp': time.time(),
            'result': data.get('result', 'blocked')
        }
        
        topology_state['attacks'].append(attack_event)
        socketio.emit('attack_event', attack_event)
        
    elif event_type == 'device_status':
        device_id = data.get('device_id')
        status = data.get('status')
        
        if device_id in topology_state['nodes']:
            topology_state['nodes'][device_id]['status'] = status
            socketio.emit('topology_update', topology_state)
    
    return jsonify({'success': True})

@app.route('/api/topology/state')
def get_topology_state():
    """Get current topology state"""
    return jsonify(topology_state)

@app.route('/api/topology/clear')
def clear_topology():
    """Clear message history"""
    topology_state['messages'] = []
    topology_state['attacks'] = []
    socketio.emit('topology_update', topology_state)
    return jsonify({'success': True})

def simulate_demo_topology():
    """Simulate topology events for demo"""
    time.sleep(2)
    
    # Device connections
    for device in ['DEVICE_A', 'DEVICE_B']:
        topology_state['nodes'][device]['status'] = 'online'
        socketio.emit('topology_update', topology_state)
        time.sleep(1)
    
    # Normal message
    message = {
        'msg_id': 'DEMO_001',
        'from': 'DEVICE_A',
        'to': 'DEVICE_B',
        'route_type': 'secure',
        'timestamp': time.time(),
        'pcap_ref': 'packet_001'
    }
    topology_state['messages'].append(message)
    socketio.emit('message_event', message)
    
    time.sleep(3)
    
    # Satellite outage - mesh fallback
    topology_state['nodes']['SATELLITE']['status'] = 'offline'
    socketio.emit('topology_update', topology_state)
    
    time.sleep(1)
    
    mesh_message = {
        'msg_id': 'DEMO_002',
        'from': 'DEVICE_A',
        'to': 'DEVICE_B',
        'route_type': 'mesh',
        'timestamp': time.time(),
        'pcap_ref': 'packet_002'
    }
    topology_state['messages'].append(mesh_message)
    socketio.emit('message_event', mesh_message)
    
    time.sleep(2)
    
    # Attack attempt
    attack = {
        'attack_type': 'MITM',
        'target': 'DEVICE_B',
        'timestamp': time.time(),
        'result': 'blocked'
    }
    topology_state['attacks'].append(attack)
    socketio.emit('attack_event', attack)

if __name__ == '__main__':
    print("🗺️ Q-SAFE Network Topology Visualizer")
    print("📡 Dashboard: http://localhost:5001")
    print("🔗 API endpoint: /api/topology/events")
    
    # Start demo simulation
    threading.Thread(target=simulate_demo_topology, daemon=True).start()
    
    try:
        socketio.run(app, host='0.0.0.0', port=5001, debug=False)
    except KeyboardInterrupt:
        print("\nTopology visualizer stopped")
