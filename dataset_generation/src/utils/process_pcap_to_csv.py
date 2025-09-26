from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, CookedLinux
import csv
import os
import sys

def _get_label_for_timestamp(timestamp, label_timeline):
    """For ongoing phases without end_time, check if timestamp >= start_time."""

    for entry in label_timeline:
        start_time = entry['start_time']
        end_time = entry.get('end_time')

        if end_time is not None:
            if start_time <= timestamp <= end_time:
                current_label = entry['label']
        else:
            if timestamp >= start_time:
                current_label = entry['label']

    return current_label

def process_pcap_to_csv(pcap_file, output_csv_file, label_timeline=None):
    print(f"Processing {os.path.basename(pcap_file)} to {os.path.basename(output_csv_file)}...")

    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        return

    packets = rdpcap(pcap_file)

    with open(output_csv_file, 'w', newline='') as csvfile:
        fieldnames = [
            'timestamp', 'packet_length', 'eth_type',
            'ip_src', 'ip_dst', 'ip_proto', 'ip_ttl', 'ip_id', 'ip_flags', 'ip_len',
            'src_port', 'dst_port',
            'tcp_flags', 'Label_multi', 'Label_binary'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for packet in packets:
            if packet.time == 0.0:
                continue

            row = {
                'timestamp': f"{float(packet.time):.6f}",
                'packet_length': len(packet),
                'eth_type': '',
                'ip_src': '',
                'ip_dst': '',
                'ip_proto': '',
                'ip_ttl': '',
                'ip_id': '',
                'ip_flags': '',
                'ip_len': '',
                'src_port': '',
                'dst_port': '',
                'tcp_flags': '',

                'Label_multi': 'unknown',
                'Label_binary': 0
            }

            if CookedLinux in packet:
                row['eth_type'] = hex(packet[CookedLinux].proto)
            elif Ether in packet:
                row['eth_type'] = hex(packet[Ether].type)

            if IP in packet:
                row['ip_src'] = packet[IP].src
                row['ip_dst'] = packet[IP].dst
                row['ip_proto'] = packet[IP].proto
                row['ip_ttl'] = packet[IP].ttl
                row['ip_id'] = packet[IP].id
                row['ip_flags'] = str(packet[IP].flags)
                row['ip_len'] = packet[IP].len

                if TCP in packet:
                    row['src_port'] = packet[TCP].sport
                    row['dst_port'] = packet[TCP].dport
                    row['tcp_flags'] = str(packet[TCP].flags)

                elif UDP in packet:
                    row['src_port'] = packet[UDP].sport
                    row['dst_port'] = packet[UDP].dport


            if label_timeline is not None:
                row['Label_multi'] = _get_label_for_timestamp(packet.time, label_timeline)
                if row['Label_multi'] != 'normal':
                    row['Label_binary'] = 1

            writer.writerow(row)

    print(f"Successfully processed {len(packets)} packets to {os.path.basename(output_csv_file)}")

if __name__ == "__main__":
    default_pcap_file = "traffic.pcap"
    default_output_csv_file = "packet_features.csv"
    default_label_timeline_file = "label_timeline.csv"

    pcap_file_arg = sys.argv[1] if len(sys.argv) > 1 else default_pcap_file
    output_csv_file_arg = sys.argv[2] if len(sys.argv) > 2 else default_output_csv_file

    timeline = None
    if os.path.exists(default_label_timeline_file):
        try:
            with open(default_label_timeline_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                timeline = []
                for row in reader:
                    timeline.append({
                        'start_time': float(row['start_time']),
                        'end_time': float(row['end_time']),
                        'label': row['label']
                    })
        except Exception as e:
            print(f"Warning: Could not read label_timeline.csv for standalone execution: {e}")

    process_pcap_to_csv(pcap_file_arg, output_csv_file_arg, timeline)
