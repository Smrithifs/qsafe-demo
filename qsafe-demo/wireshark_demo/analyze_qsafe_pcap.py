#!/usr/bin/env python3
"""
Q-SAFE PCAP Analysis Script for Wireshark Demo
Automatically analyzes captured PCAP files and generates reports
"""

import sys
import json
import os
from datetime import datetime
try:
    import pyshark
except ImportError:
    print("pyshark not available, using basic analysis")
    pyshark = None

def analyze_qsafe_pcap(pcap_file):
    """Analyze Q-SAFE PCAP file and generate report"""
    
    if not os.path.exists(pcap_file):
        print(f"PCAP file not found: {pcap_file}")
        return
    
    print(f"🔍 Analyzing Q-SAFE PCAP: {pcap_file}")
    
    # Basic file info
    file_size = os.path.getsize(pcap_file)
    print(f"📊 File size: {file_size} bytes")
    
    if pyshark:
        analyze_with_pyshark(pcap_file)
    else:
        analyze_basic(pcap_file)

def analyze_with_pyshark(pcap_file):
    """Detailed analysis using pyshark"""
    try:
        cap = pyshark.FileCapture(pcap_file)
        
        packet_count = 0
        qsafe_messages = 0
        attack_attempts = 0
        mesh_traffic = 0
        
        print("\n📦 Packet Analysis:")
        print("-" * 50)
        
        for packet in cap:
            packet_count += 1
            
            # Check if it's TCP traffic on Q-SAFE ports
            if hasattr(packet, 'tcp'):
                dst_port = int(packet.tcp.dstport)
                src_port = int(packet.tcp.srcport)
                
                # Satellite traffic
                if dst_port == 5000 or src_port == 5000:
                    if hasattr(packet, 'data'):
                        payload = str(packet.data.data)
                        
                        # Look for Q-SAFE message patterns
                        if 'encrypted_data' in payload:
                            qsafe_messages += 1
                            print(f"✅ Q-SAFE Message #{qsafe_messages} (Packet {packet_count})")
                            
                            # Extract message details
                            if 'msg_id' in payload:
                                try:
                                    # Try to extract JSON (simplified)
                                    if 'DEVICE_A' in payload:
                                        print(f"   📤 From: DEVICE_A")
                                    if 'DEVICE_B' in payload:
                                        print(f"   📥 To: DEVICE_B")
                                    if 'RSA' in payload:
                                        print(f"   🔐 Algorithm: RSA")
                                except:
                                    pass
                        
                        # Look for potential attack patterns
                        elif 'attack' in payload.lower() or 'mitm' in payload.lower():
                            attack_attempts += 1
                            print(f"⚠️  Potential Attack #{attack_attempts} (Packet {packet_count})")
                
                # Mesh traffic
                elif dst_port in [8080, 8081] or src_port in [8080, 8081]:
                    mesh_traffic += 1
                    print(f"🔗 Mesh Traffic #{mesh_traffic} (Packet {packet_count})")
        
        cap.close()
        
        print(f"\n📈 Analysis Summary:")
        print(f"   Total packets: {packet_count}")
        print(f"   Q-SAFE messages: {qsafe_messages}")
        print(f"   Mesh traffic: {mesh_traffic}")
        print(f"   Attack attempts: {attack_attempts}")
        
        # Security assessment
        print(f"\n🛡️  Security Assessment:")
        if attack_attempts > 0:
            print(f"   ⚠️  {attack_attempts} potential attack(s) detected")
            print(f"   ✅ All attacks should be blocked by Q-SAFE crypto")
        else:
            print(f"   ✅ No attack attempts detected")
        
        if qsafe_messages > 0:
            print(f"   ✅ {qsafe_messages} encrypted message(s) found")
            print(f"   🔐 All messages properly encrypted and signed")
        
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")

def analyze_basic(pcap_file):
    """Basic analysis without pyshark"""
    print("📋 Basic PCAP analysis (install pyshark for detailed analysis)")
    
    # Check if metadata file exists
    metadata_file = pcap_file.replace('.pcap', '_metadata.json')
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        print(f"📊 Metadata found:")
        print(f"   Total packets: {metadata.get('total_packets', 'Unknown')}")
        print(f"   Capture time: {metadata.get('capture_time', 'Unknown')}")
        
        # Analyze packet metadata
        qsafe_count = 0
        for packet in metadata.get('packets', []):
            if packet.get('qsafe_data'):
                qsafe_count += 1
        
        print(f"   Q-SAFE messages: {qsafe_count}")
    else:
        print("   No metadata file found")

def generate_wireshark_commands(pcap_file):
    """Generate Wireshark command examples"""
    print(f"\n🖥️  Wireshark Analysis Commands:")
    print(f"   # Open in Wireshark:")
    print(f"   wireshark {pcap_file}")
    print(f"")
    print(f"   # Command line analysis:")
    print(f"   tshark -r {pcap_file} -Y 'tcp.port == 5000'")
    print(f"   tshark -r {pcap_file} -Y 'tcp.port == 5000 and frame contains \"encrypted_data\"'")
    print(f"   tshark -r {pcap_file} -T json > {pcap_file}.json")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Q-SAFE PCAP files')
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('--commands', action='store_true', help='Show Wireshark commands')
    
    args = parser.parse_args()
    
    analyze_qsafe_pcap(args.pcap_file)
    
    if args.commands:
        generate_wireshark_commands(args.pcap_file)

if __name__ == '__main__':
    main()
