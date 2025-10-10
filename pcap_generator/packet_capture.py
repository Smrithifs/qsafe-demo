#!/usr/bin/env python3
"""
PCAP Generator for Q-SAFE Demo
Creates real packet captures for Wireshark analysis
"""

import time
import json
import threading
import socket
from datetime import datetime
from scapy.all import *
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class QSafePcapGenerator:
    def __init__(self, output_dir="logs"):
        self.output_dir = output_dir
        self.captured_packets = []
        self.packet_metadata = []
        self.capture_active = False
        self.packet_count = 0
        
        os.makedirs(output_dir, exist_ok=True)
    
    def start_capture(self, interface="lo0", filter_expr="port 5000"):
        """Start packet capture with scapy"""
        def packet_handler(packet):
            if self.capture_active:
                self.packet_count += 1
                timestamp = time.time()
                
                # Store packet
                self.captured_packets.append(packet)
                
                # Extract metadata
                metadata = {
                    'packet_id': self.packet_count,
                    'timestamp': timestamp,
                    'size': len(packet),
                    'src': None,
                    'dst': None,
                    'protocol': None,
                    'qsafe_data': None
                }
                
                # Extract network info
                if packet.haslayer(IP):
                    metadata['src'] = packet[IP].src
                    metadata['dst'] = packet[IP].dst
                    metadata['protocol'] = packet[IP].proto
                
                # Check for Q-SAFE message data
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8')
                        if 'encrypted_data' in payload or 'msg_id' in payload:
                            qsafe_msg = json.loads(payload)
                            metadata['qsafe_data'] = {
                                'msg_id': qsafe_msg.get('msg_id'),
                                'from': qsafe_msg.get('from'),
                                'to': qsafe_msg.get('to'),
                                'algorithm': qsafe_msg.get('algorithm'),
                                'ciphertext_size': len(qsafe_msg.get('encrypted_data', {}).get('ciphertext', ''))
                            }
                    except:
                        pass
                
                self.packet_metadata.append(metadata)
                print(f"[PCAP] Captured packet {self.packet_count}: {metadata['src']} → {metadata['dst']}")
        
        def capture_thread():
            print(f"[PCAP] Starting capture on {interface} with filter: {filter_expr}")
            self.capture_active = True
            sniff(iface=interface, prn=packet_handler, filter=filter_expr, store=False)
        
        threading.Thread(target=capture_thread, daemon=True).start()
    
    def save_pcap(self, filename="qsafe_demo.pcap"):
        """Save captured packets to PCAP file"""
        if not self.captured_packets:
            print("[PCAP] No packets to save")
            return None
            
        pcap_path = os.path.join(self.output_dir, filename)
        
        # Add comments to packets
        annotated_packets = []
        for i, packet in enumerate(self.captured_packets):
            metadata = self.packet_metadata[i]
            
            # Create packet comment
            comment = f"Q-SAFE Demo Packet {metadata['packet_id']}"
            if metadata['qsafe_data']:
                qdata = metadata['qsafe_data']
                comment += f" | MSG_ID: {qdata['msg_id']} | {qdata['from']}→{qdata['to']} | ALG: {qdata['algorithm']}"
            
            # Add comment as packet annotation (Wireshark will show this)
            packet.comment = comment
            annotated_packets.append(packet)
        
        # Write PCAP file
        wrpcap(pcap_path, annotated_packets)
        
        # Create metadata JSON
        metadata_path = pcap_path.replace('.pcap', '_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump({
                'pcap_file': filename,
                'capture_time': datetime.now().isoformat(),
                'total_packets': len(self.captured_packets),
                'packets': self.packet_metadata
            }, f, indent=2)
        
        print(f"[PCAP] Saved {len(self.captured_packets)} packets to {pcap_path}")
        print(f"[PCAP] Metadata saved to {metadata_path}")
        
        return pcap_path
    
    def create_sample_pcap(self):
        """Create sample PCAP with Q-SAFE message for judges"""
        sample_packets = []
        
        # Create synthetic Q-SAFE message packet
        qsafe_message = {
            'msg_id': 'DEMO_001',
            'from': 'DEVICE_A',
            'to': 'DEVICE_B',
            'encrypted_data': {
                'encrypted_session_key': 'a1b2c3d4e5f6' * 20,  # 120 hex chars
                'iv': '1234567890abcdef' * 2,  # 32 hex chars
                'ciphertext': 'deadbeef' * 50,  # 400 hex chars of encrypted data
                'auth_tag': 'cafebabe' * 4,  # 32 hex chars
                'algorithm': 'RSA',
                'timestamp': time.time()
            },
            'signature': 'fedcba9876543210' * 8,  # 128 hex chars
            'timestamp': time.time(),
            'algorithm': 'RSA'
        }
        
        # Create packet with this payload
        payload = json.dumps(qsafe_message).encode('utf-8')
        packet = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=12345, dport=5000)/Raw(load=payload)
        packet.comment = "Q-SAFE Demo Message | MSG_ID: DEMO_001 | DEVICE_A→DEVICE_B | Contains encrypted payload"
        
        sample_packets.append(packet)
        
        # Save sample PCAP
        sample_path = os.path.join(self.output_dir, "sample_mitm_attempt.pcap")
        wrpcap(sample_path, sample_packets)
        
        print(f"[PCAP] Created sample PCAP: {sample_path}")
        return sample_path
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        print(f"[PCAP] Capture stopped. Total packets: {self.packet_count}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Q-SAFE PCAP Generator')
    parser.add_argument('--output', default='logs', help='Output directory')
    parser.add_argument('--interface', default='lo0', help='Network interface to capture')
    parser.add_argument('--filter', default='port 5000', help='Capture filter')
    parser.add_argument('--duration', type=int, default=30, help='Capture duration in seconds')
    parser.add_argument('--sample', action='store_true', help='Create sample PCAP only')
    
    args = parser.parse_args()
    
    generator = QSafePcapGenerator(args.output)
    
    if args.sample:
        generator.create_sample_pcap()
        return
    
    try:
        generator.start_capture(args.interface, args.filter)
        print(f"Capturing for {args.duration} seconds...")
        time.sleep(args.duration)
        
    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    finally:
        generator.stop_capture()
        pcap_file = generator.save_pcap()
        if pcap_file:
            print(f"PCAP saved: {pcap_file}")

if __name__ == '__main__':
    main()
