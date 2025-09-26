#!/usr/bin/env python3
import io
import sys
import re
import os
import signal
import time
import logging
import argparse
import subprocess
import threading
from pathlib import Path
import shutil
import site
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, Raw, sr1, send
from src.gen_benign_traffic import run_benign_traffic
import requests
import pandas as pd
from datetime import datetime
import json
from multiprocessing import cpu_count
from concurrent.futures import ProcessPoolExecutor

# Built-in modules for zero-installation enhancements
import statistics
import math
import hashlib
import collections
import calendar
import base64
import random
import socket
import importlib.util

# Optional psutil import - gracefully handle if missing
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("WARNING: psutil not available - CPU affinity features will be disabled")

# Import standardized logging
from src.utils.logger import get_main_logger, ConsoleOutput, initialize_logging, print_dataset_summary
from src.utils.timeline_analysis import analyze_dataset_timeline, print_detailed_timeline_report

# Enhanced PCAP processing
from src.utils.process_pcap_to_csv import process_pcap_to_csv
from src.utils.enhanced_pcap_processing import (
    validate_and_fix_pcap_timestamps,
    enhanced_process_pcap_to_csv,
    improve_capture_reliability,
    verify_pcap_integrity,
    analyze_pcap_for_tcp_issues,
    analyze_inter_packet_arrival_time
)
from src.utils.process_pcap_to_csv import _get_label_for_timestamp

# Mininet imports
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Add attacks directory to Python path
sys.path.append(str(Path(__file__).parent.resolve() / "src" / "attacks"))
from gen_syn_flood import run_attack as run_syn_flood
from gen_udp_flood import run_attack as run_udp_flood
from enhanced_icmp_flood import run_attack as run_icmp_flood

# Configuration
BASE_DIR = Path(__file__).parent.resolve()
SRC_DIR = BASE_DIR / "src"
ATTACKS_DIR = SRC_DIR / "attacks"
UTILS_DIR = SRC_DIR / "utils"
OUTPUT_DIR = BASE_DIR / "main_output"
PCAP_FILE_NORMAL = OUTPUT_DIR / "normal.pcap"
PCAP_FILE_SYN_FLOOD = OUTPUT_DIR / "syn_flood.pcap"
PCAP_FILE_UDP_FLOOD = OUTPUT_DIR / "udp_flood.pcap"
PCAP_FILE_ICMP_FLOOD = OUTPUT_DIR / "icmp_flood.pcap"
OUTPUT_CSV_FILE = OUTPUT_DIR / "packet_features.csv"
OUTPUT_FLOW_CSV_FILE = OUTPUT_DIR / "flow_features.csv"
OUTPUT_CICFLOW_CSV_FILE = OUTPUT_DIR / "cicflow_features.csv"
RYU_CONTROLLER_APP = SRC_DIR / "controller" / "ryu_l3_router_app.py"

# Host IPs - 4 Subnet Configuration
HOST_IPS = {
    "h1": "192.168.10.10",  # Subnet 1: 192.168.10.0/24
    "h2": "192.168.20.10",  # Subnet 2: 192.168.20.0/24 
    "h3": "192.168.20.11",  # Subnet 2: 192.168.20.0/24
    "h4": "192.168.20.12",  # Subnet 2: 192.168.20.0/24
    "h5": "192.168.20.13",  # Subnet 2: 192.168.20.0/24
    "h6": "192.168.30.10"   # Subnet 3: 192.168.30.0/24
}

# Subnet Gateway Configuration
SUBNET_GATEWAYS = {
    "192.168.10.0/24": "192.168.10.1",
    "192.168.20.0/24": "192.168.20.1", 
    "192.168.30.0/24": "192.168.30.1",
    "192.168.0.0/24": "192.168.0.1"  # Controller network
}

RESOLVED_TOOL_PATHS = {}

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = False

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# File handler
file_handler = logging.FileHandler(OUTPUT_DIR / 'main.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# Attack logger
attack_logger = logging.getLogger('attack_logger')
attack_logger.setLevel(logging.DEBUG)
attack_logger.propagate = False

# File handler for attack.log
attack_log_file_handler = logging.FileHandler(OUTPUT_DIR / 'attack.log')
attack_log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
attack_logger.addHandler(attack_log_file_handler)

# Console handler for attack_logger
class AttackConsoleFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        if any(phrase in message for phrase in [
            "did not terminate gracefully, forcing termination",
            "slowhttptest process exited with non-zero code: -15"
        ]):
            return False
        return True

attack_console_handler = logging.StreamHandler()
attack_console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
attack_console_handler.setLevel(logging.WARNING)
attack_console_handler.addFilter(AttackConsoleFilter())
attack_logger.addHandler(attack_console_handler)

# Suppress debug messages
logging.getLogger("urllib3").setLevel(logging.WARNING)


# =============================================================================
# 30-FEATURE EXTRACTION ENGINE
# =============================================================================

def extract_30_features_from_packet(packet, capture_time=None):
    features = {
        # Initialize all features with empty values
        'timestamp': capture_time if capture_time else time.time(),
        'eth_type': '',
        'ip_src': '',
        'ip_dst': '',
        'ip_proto': '',
        'ip_ttl': '',
        'ip_id': '',
        'ip_flags': '',
        'ip_len': '',
        'ip_tos': '',
        'ip_version': '',
        'ip_frag_offset': '',
        'src_port': '',
        'dst_port': '',
        'tcp_flags': '',
        'tcp_seq': '',
        'tcp_ack': '',
        'tcp_window': '',
        'tcp_urgent': '',
        'udp_sport': '',
        'udp_dport': '',
        'udp_len': '',
        'udp_checksum': '',
        'icmp_type': '',
        'icmp_code': '',
        'icmp_id': '',
        'icmp_seq': '',
        'packet_length': len(packet),
        'transport_protocol': '',
        'tcp_options_len': ''
    }
    
    try:
        # Ethernet layer
        if hasattr(packet, 'type'):
            features['eth_type'] = hex(packet.type)
        elif Ether in packet:
            features['eth_type'] = hex(packet[Ether].type)
        
        # IP layer
        if IP in packet:
            ip = packet[IP]
            features.update({
                'ip_src': ip.src,
                'ip_dst': ip.dst,
                'ip_proto': ip.proto,
                'ip_ttl': ip.ttl,
                'ip_id': ip.id,
                'ip_flags': str(ip.flags),
                'ip_len': ip.len,
                'ip_tos': ip.tos,
                'ip_version': ip.version,
                'ip_frag_offset': ip.frag
            })
            
            # Protocol-specific extraction
            if TCP in packet:
                tcp = packet[TCP]
                features.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': str(tcp.flags),
                    'tcp_seq': tcp.seq,
                    'tcp_ack': tcp.ack,
                    'tcp_window': tcp.window,
                    'tcp_urgent': tcp.urgptr,
                    'tcp_options_len': len(tcp.options) if hasattr(tcp, 'options') else 0,
                    'transport_protocol': 'TCP'
                })
            elif UDP in packet:
                udp = packet[UDP]
                features.update({
                    'udp_sport': udp.sport,
                    'udp_dport': udp.dport,
                    'udp_len': udp.len,
                    'udp_checksum': udp.chksum,
                    'transport_protocol': 'UDP'
                })
            elif ICMP in packet:
                icmp = packet[ICMP]
                features.update({
                    'icmp_type': icmp.type,
                    'icmp_code': icmp.code,
                    'icmp_id': getattr(icmp, 'id', ''),
                    'icmp_seq': getattr(icmp, 'seq', ''),
                    'transport_protocol': 'ICMP'
                })
    
    except Exception as e:
        logger.debug(f"Error extracting features from packet: {e}")
    
    return features


def process_pcap_to_30_features_csv(pcap_file_path, output_csv_path, label_timeline, worker_logger=None, time_offset: float = 0.0):
    import traceback
    
    # Create logger if not provided (for multiprocessing compatibility)
    if worker_logger is None:
        worker_logger = logging.getLogger(f'pcap_processor_{int(time.time())}')
        worker_logger.setLevel(logging.INFO)
    
    worker_logger.info(f"=== CORE PCAP PROCESSING START ===")
    worker_logger.info(f"Input PCAP: {pcap_file_path}")
    worker_logger.info(f"Output CSV: {output_csv_path}")
    worker_logger.info(f"Label timeline: {label_timeline}")
    if abs(time_offset) > 0.000001:
        worker_logger.info(f"Applying time offset to packet timestamps: {time_offset:.6f} seconds")
    
    try:
        # Step A: Load PCAP file using Scapy
        worker_logger.info("Step A: Loading PCAP file with Scapy...")
        try:
            from scapy.all import rdpcap
            worker_logger.info("[OK] Scapy rdpcap import successful")
        except ImportError as scapy_e:
            worker_logger.error(f"[FAIL] Scapy import failed: {scapy_e}")
            worker_logger.error(f"Scapy import traceback: {traceback.format_exc()}")
            return None
        
        try:
            packets = rdpcap(str(pcap_file_path))
            worker_logger.info(f"[OK] Loaded {len(packets)} packets from {pcap_file_path}")
        except Exception as rdpcap_e:
            worker_logger.error(f"[FAIL] Error loading PCAP with rdpcap: {rdpcap_e}")
            worker_logger.error(f"rdpcap error type: {type(rdpcap_e).__name__}")
            worker_logger.error(f"rdpcap traceback: {traceback.format_exc()}")
            return None
        
        # Step B: Validate packet count
        if len(packets) == 0:
            worker_logger.error(f"[FAIL] No packets found in {pcap_file_path}")
            return None
        
        # Step C: Timeline validation
        worker_logger.info("Step B: Validating timeline...")
        if not label_timeline:
            worker_logger.error(f"[FAIL] No label timeline provided - cannot proceed")
            return None
        else:
            worker_logger.info(f"[OK] Using label timeline with {len(label_timeline)} phases for proper labeling")
            worker_logger.info(f"Timeline details: {label_timeline}")
        
        # Step D: Process packets
        worker_logger.info("Step C: Processing packets...")
        packet_features = []
        packets_discarded = 0
        packets_processed = 0
        packet_errors = 0
        
        for i, packet in enumerate(packets):
            try:
                packets_processed += 1
                
                # Extract timestamp from packet
                if hasattr(packet, 'time'):
                    packet_timestamp = float(packet.time)
                else:
                    packet_timestamp = time.time()
                    worker_logger.debug(f"Packet {i} missing timestamp, using current time")
                
                # Extract 30 features
                try:
                    features = extract_30_features_from_packet(packet, packet_timestamp)
                except Exception as feature_e:
                    worker_logger.debug(f"Error extracting features from packet {i}: {feature_e}")
                    packet_errors += 1
                    continue
                
                # Add labels based on label timeline (apply optional time offset to align with master timeline)
                try:
                    adjusted_ts = packet_timestamp + time_offset
                    label_multi = _get_label_for_timestamp(adjusted_ts, label_timeline)
                    label_binary = 1 if label_multi != 'normal' else 0
                    
                    # Only keep packets with valid labels
                    valid_labels = {'normal', 'syn_flood', 'udp_flood', 'icmp_flood'}
                    if label_multi in valid_labels:
                        features['Label_multi'] = label_multi
                        features['Label_binary'] = label_binary
                        packet_features.append(features)
                    else:
                        packets_discarded += 1  # Count discarded packets with invalid labels
                        worker_logger.debug(f"Packet {i} discarded - invalid label: {label_multi}")
                        
                except Exception as labeling_e:
                    worker_logger.debug(f"Error labeling packet {i}: {labeling_e}")
                    packets_discarded += 1
                    continue
                
                # Progress logging
                if (i + 1) % 5000 == 0:
                    worker_logger.info(f"Processed {i + 1}/{len(packets)} packets...")
                    
            except Exception as packet_e:
                worker_logger.debug(f"Error processing packet {i}: {packet_e}")
                packet_errors += 1
                continue
        
        worker_logger.info(f"Packet processing complete: {packets_processed} processed, {len(packet_features)} kept, {packets_discarded} discarded, {packet_errors} errors")
        
        # Step E: Create and save DataFrame
        if packet_features:
            worker_logger.info("Step D: Creating DataFrame and saving to CSV...")
            try:
                # Create DataFrame with specific column order
                column_order = [
                    'timestamp', 'eth_type', 'ip_src', 'ip_dst', 'ip_proto', 'ip_ttl', 'ip_id', 
                    'ip_flags', 'ip_len', 'ip_tos', 'ip_version', 'ip_frag_offset', 'src_port', 
                    'dst_port', 'tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window', 'tcp_urgent', 
                    'udp_sport', 'udp_dport', 'udp_len', 'udp_checksum', 'icmp_type', 'icmp_code', 
                    'icmp_id', 'icmp_seq', 'packet_length', 'transport_protocol', 'tcp_options_len',
                    'Label_multi', 'Label_binary'
                ]
                
                df = pd.DataFrame(packet_features)
                worker_logger.info(f"[OK] DataFrame created: {len(df)} rows, {len(df.columns)} columns")
                
                df = df.reindex(columns=column_order)
                worker_logger.info(f"[OK] DataFrame reindexed to standard column order")
                
                df.to_csv(output_csv_path, index=False)
                worker_logger.info(f"[OK] CSV saved to {output_csv_path}")
                
                # Final statistics
                packets_kept = len(packet_features)
                worker_logger.info(f"=== PROCESSING SUMMARY ===")
                worker_logger.info(f"Total packets in PCAP: {len(packets)}")
                worker_logger.info(f"Packets processed: {packets_processed}")
                worker_logger.info(f"Packets kept: {packets_kept}")
                worker_logger.info(f"Packets discarded: {packets_discarded}")
                worker_logger.info(f"Packet errors: {packet_errors}")
                worker_logger.info(f"Success rate: {packets_kept/len(packets)*100:.1f}%")
                worker_logger.info(f"=== CORE PCAP PROCESSING SUCCESS ===")
                
                return df
                
            except Exception as df_e:
                worker_logger.error(f"[FAIL] Error creating/saving DataFrame: {df_e}")
                worker_logger.error(f"DataFrame error traceback: {traceback.format_exc()}")
                return None
        else:
            worker_logger.error(f"[FAIL] No valid packets processed from {pcap_file_path}")
            worker_logger.error(f"Total processed: {packets_processed}, Discarded: {packets_discarded}, Errors: {packet_errors}")
            worker_logger.error(f"=== CORE PCAP PROCESSING FAILED - NO VALID PACKETS ===")
            return None
            
    except Exception as e:
        worker_logger.error(f"[FAIL] CRITICAL ERROR in core PCAP processing: {e}")
        worker_logger.error(f"Error type: {type(e).__name__}")
        worker_logger.error(f"Full traceback: {traceback.format_exc()}")
        worker_logger.error(f"=== CORE PCAP PROCESSING FAILED - CRITICAL ERROR ===")
        return None


# =============================================================================
# CPU CORE ALLOCATION FOR OPTIMAL PERFORMANCE
# =============================================================================

class CPUCoreManager:
    """Manages CPU core allocation for different modules using taskset"""
    
    def __init__(self, total_cores=16):
        self.total_cores = total_cores
        self.core_allocation = self._calculate_core_allocation()
        
    def _calculate_core_allocation(self):
        """Calculate optimal core allocation based on total cores"""
        if self.total_cores >= 16:
            return {
                'system': [0],                    # Core 0: System/OS
                'ryu': [1],                       # Core 1: Ryu Controller
                'mininet': [2, 3, 4],            # Cores 2-4: Mininet Network (3 cores)
                'attacks': [5, 6, 7, 8, 9, 10],  # Cores 5-10: Attack Generation (6 cores)
                'background': [11],               # Core 11: Background Services
                'pcap': list(range(self.total_cores))  # All cores for PCAP processing
            }
        elif self.total_cores >= 12:
            return {
                'system': [0],
                'ryu': [1],
                'mininet': [2, 3],
                'attacks': [4, 5, 6, 7, 8],
                'background': [9],
                'pcap': list(range(self.total_cores))
            }
        elif self.total_cores >= 8:
            return {
                'system': [0],
                'ryu': [1],
                'mininet': [2, 3],
                'attacks': [4, 5, 6],
                'background': [7],
                'pcap': list(range(self.total_cores))
            }
        elif self.total_cores == 1:
            # Single core system - all processes share core 0
            return {
                'system': [0],
                'ryu': [0],
                'mininet': [0],
                'attacks': [0],
                'background': [0],
                'pcap': [0]
            }
        else:
            # Default allocation for 2-7 cores
            return {
                'system': [0],
                'ryu': [1] if self.total_cores > 1 else [0],
                'mininet': [2] if self.total_cores > 2 else [0],
                'attacks': [3] if self.total_cores > 3 else [0],
                'background': [0],  # Share with system
                'pcap': list(range(self.total_cores))
            }
    
    def set_process_affinity(self, process_type, pid=None):
        """Set CPU affinity for a process type"""
        if process_type not in self.core_allocation:
            logger.warning(f"Unknown process type: {process_type}")
            return False
            
        cores = self.core_allocation[process_type]
        
        try:
            if pid is None:
                # Set affinity for current process
                os.sched_setaffinity(0, cores)
                logger.info(f"[OK] Set current process affinity to cores {cores} for {process_type}")
            else:
                # Set affinity for specific PID
                os.sched_setaffinity(pid, cores)
                logger.info(f"[OK] Set PID {pid} affinity to cores {cores} for {process_type}")
            return True
        except Exception as e:
            logger.error(f"[FAIL] Failed to set CPU affinity for {process_type}: {e}")
            return False
    
    def start_process_with_affinity(self, process_type, cmd, **kwargs):
        """Start a process with specific CPU affinity using taskset"""
        cores = self.core_allocation[process_type]
        core_list = ','.join(map(str, cores))
        
        # Prepend taskset command
        taskset_cmd = ['taskset', '-c', core_list] + cmd
        
        logger.info(f"[RUN] Starting {process_type} on cores {cores}: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(taskset_cmd, **kwargs)
            logger.info(f"[OK] Started {process_type} with PID {process.pid} on cores {cores}")
            return process
        except Exception as e:
            logger.error(f"[FAIL] Failed to start {process_type} with taskset: {e}")
            # Fallback to regular process start
            process = subprocess.Popen(cmd, **kwargs)
            logger.warning(f"[WARN]  Started {process_type} with PID {process.pid} without CPU affinity")
            return process
    
    def get_core_info(self):
        """Get core allocation information"""
        return self.core_allocation
    
    def print_allocation(self):
        """Print current core allocation"""
        logger.info("[TOOLS] CPU Core Allocation:")
        for process_type, cores in self.core_allocation.items():
            if process_type == 'pcap':
                logger.info(f"  {process_type.capitalize()}: Cores {cores[0]}-{cores[-1]} (all cores, post-simulation)")
            else:
                core_str = ','.join(map(str, cores))
                logger.info(f"  {process_type.capitalize()}: Cores {core_str}")

# Initialize CPU core manager (will be set in main())
cpu_manager = None


# =============================================================================
# DDoS ATTACKS
# =============================================================================

class IPRotator:
    """RFC 1918 private IP rotation for attacks"""
    
    def __init__(self):
        # RFC 1918 private IP address ranges for realistic IP rotation
        self.ip_ranges = {
            '10.0.0.0/8': ('10.0.0.1', '10.255.255.254'),
            '172.16.0.0/12': ('172.16.0.1', '172.31.255.254'), 
            '192.168.0.0/16': ('192.168.0.1', '192.168.255.254')
        }
    
    def get_random_ip(self):
        """Generate random IP from RFC 1918 private ranges"""
        # Select random range
        range_choice = random.choice(list(self.ip_ranges.keys()))
        
        if range_choice == '10.0.0.0/8':
            # 10.x.x.x
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif range_choice == '172.16.0.0/12':
            # 172.16-31.x.x
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:  # 192.168.0.0/16
            # 192.168.x.x
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"


# Enhanced attack runner function


# =============================================================================
# MAIN FRAMEWORK FUNCTIONALITY
# =============================================================================


def _build_search_paths():
    path_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]

    extra_dirs = [
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/bin"),
        Path("/sbin"),
        Path.home() / ".local/bin",
        Path(sys.executable).parent,
    ]

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        sudo_home = Path("/home") / sudo_user
        extra_dirs.extend([sudo_home / ".local/bin", sudo_home / ".local/sbin"])

    for directory in extra_dirs:
        if directory and directory.exists():
            path_entries.append(str(directory))

    seen = set()
    unique_paths = []
    for entry in path_entries:
        if entry and entry not in seen:
            unique_paths.append(entry)
            seen.add(entry)

    return unique_paths


def _resolve_tool_path(tool: str, search_paths=None):
    paths = search_paths or _build_search_paths()
    combined_path = os.pathsep.join(paths)
    found = shutil.which(tool, path=combined_path)
    if found:
        return Path(found)

    for entry in paths:
        candidate = Path(entry) / tool
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate

    return None


def _get_python_site_dirs():
    """Return candidate site-packages directories that may contain user-installed modules."""
    candidates = []

    try:
        for path in site.getsitepackages():
            candidates.append(Path(path))
    except Exception:
        pass

    try:
        user_site = site.getusersitepackages()
        candidates.append(Path(user_site))
    except Exception:
        pass

    std_user = Path.home() / f".local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    candidates.append(std_user)

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != os.environ.get("USER"):
        sudo_home = Path('/home') / sudo_user
        candidates.append(sudo_home / f".local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")

    unique = []
    seen = set()
    for candidate in candidates:
        try:
            candidate = candidate.resolve()
        except Exception:
            continue
        if candidate.exists():
            key = str(candidate)
            if key not in seen:
                unique.append(key)
                seen.add(key)
    return unique

def ensure_python_paths():
    """Ensure important site-package directories are on sys.path."""
    for directory in _get_python_site_dirs():
        if directory not in sys.path:
            sys.path.insert(0, directory)
def verify_tools():
    """Verify that all required command-line tools are installed."""
    logger.info("Verifying required tools...")
    try:
        tshark_output = subprocess.check_output(["tshark", "--version"], universal_newlines=True, stderr=subprocess.STDOUT)
        version_line = tshark_output.split("\n")[0] if tshark_output else "unknown"
        logger.info(f"TShark version: {version_line}")
    except Exception as e:
        logger.error(f"Could not get TShark version: {e}")
        logger.error("Please install Wireshark/tshark package.")
        sys.exit(1)


    ensure_python_paths()
    search_paths = _build_search_paths()
    os.environ["PATH"] = os.pathsep.join(search_paths)

    required_tools = ["ryu-manager", "mn", "tshark", "tcpdump", "slowhttptest", "taskset"]
    missing_tools = []

    for tool in required_tools:
        tool_path = _resolve_tool_path(tool, search_paths)
        if tool_path is None:
            missing_tools.append(tool)
            logger.error(f"Tool not found: '{tool}'. Please install it manually.")
            if tool == "tshark":
                logger.error("On Ubuntu/Debian: sudo apt-get install tshark")
                logger.error("On CentOS/RHEL: sudo yum install wireshark")
            elif tool == "tcpdump":
                logger.error("On Ubuntu/Debian: sudo apt-get install tcpdump")
                logger.error("On CentOS/RHEL: sudo yum install tcpdump")
            elif tool == "taskset":
                logger.error("On Ubuntu/Debian: sudo apt-get install util-linux")
                logger.error("On CentOS/RHEL: sudo yum install util-linux")
            elif tool == "ryu-manager":
                logger.error("If ryu-manager is installed for a non-root user, add that user's ~/.local/bin to PATH before running with sudo.")
        else:
            RESOLVED_TOOL_PATHS[tool] = str(tool_path)
            logger.info(f"[TOOLS] {tool}: {tool_path}")

    if missing_tools:
        sys.exit(1)

    # Verify Ryu module is available
    try:
        ryu_spec = importlib.util.find_spec("ryu")
        if ryu_spec and ryu_spec.origin:
            ryu_module_path = Path(ryu_spec.origin).resolve()
            RESOLVED_TOOL_PATHS["ryu_module"] = str(ryu_module_path)
    except Exception:
        pass  # ryu-manager tool check is sufficient

    logger.info("All required tools are available.")

def start_controller():
    """Start the Ryu SDN controller as a background process with CPU affinity."""
    if not RYU_CONTROLLER_APP.exists():
        logger.error(f"Ryu controller application not found at: {RYU_CONTROLLER_APP}")
        sys.exit(1)
        
    logger.info("Starting Ryu SDN controller with CPU affinity...")
    ryu_log_file = OUTPUT_DIR / "ryu.log"
    ryu_cmd = [
        "python3", "-m", "ryu.cmd.manager",
        "--verbose",
        str(RYU_CONTROLLER_APP)
    ]

    env = os.environ.copy()
    env_paths = _build_search_paths()
    env["PATH"] = os.pathsep.join(env_paths)
    python_site_dirs = _get_python_site_dirs()
    existing_pythonpath = env.get("PYTHONPATH")
    if existing_pythonpath:
        python_site_dirs.extend(existing_pythonpath.split(os.pathsep))
    unique_python_paths = []
    seen_python = set()
    for path_entry in python_site_dirs:
        if path_entry and path_entry not in seen_python:
            unique_python_paths.append(path_entry)
            seen_python.add(path_entry)
    if unique_python_paths:
        env["PYTHONPATH"] = os.pathsep.join(unique_python_paths)
    resolved_ryu = RESOLVED_TOOL_PATHS.get("ryu-manager")
    if resolved_ryu:
        ryu_dir = str(Path(resolved_ryu).parent)
        if ryu_dir not in seen_python:
            env["PYTHONPATH"] = os.pathsep.join(unique_python_paths + [ryu_dir]) if unique_python_paths else ryu_dir
    ryu_module_path = RESOLVED_TOOL_PATHS.get("ryu_module")
    if ryu_module_path:
        module_dir = str(Path(ryu_module_path).parent)
        if module_dir not in seen_python:
            env["PYTHONPATH"] = os.pathsep.join((unique_python_paths + [module_dir])) if unique_python_paths else module_dir
            unique_python_paths.append(module_dir)
            seen_python.add(module_dir)
    logger.info(f'[TOOLS] PYTHONPATH for Ryu: {env.get("PYTHONPATH")}')

    
    with open(ryu_log_file, 'wb') as log_out:
        if cpu_manager:
            # Use CPU affinity if manager is available
            process = cpu_manager.start_process_with_affinity('ryu', ryu_cmd, stdout=log_out, stderr=log_out, env=env)
        else:
            # Fallback to regular process start
            process = subprocess.Popen(ryu_cmd, stdout=log_out, stderr=log_out, env=env)
    
    logger.info(f"Ryu controller started with PID: {process.pid}. See {ryu_log_file.relative_to(BASE_DIR)} for logs.")
    return process

def check_controller_health(port=6653, timeout=30):
    """Check if the controller is listening on its port."""
    logger.info(f"Checking for controller on port {port} (timeout: {timeout}s)...")
    for _ in range(timeout):
        try:
            result = subprocess.run(["ss", "-ltn"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
            if f":{port}" in result.stdout:
                logger.info("Controller is up and listening.")
                return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            try:
                result = subprocess.run(["netstat", "-ltn"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
                if f":{port}" in result.stdout:
                    logger.info("Controller is up and listening.")
                    return True
            except Exception:
                logger.warning("Could not check controller port. Assuming it will be ready.", exc_info=True)
                return True
        time.sleep(1)
    logger.error(f"Controller did not become available on port {port} within {timeout} seconds.")
    return False

class ScenarioTopo(Topo):
    """Custom 4-subnet topology for enterprise dataset generation."""
    def build(self, **_opts):
        s1 = self.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")
        
        # Configure hosts with proper subnet settings and default gateways
        # Subnet 1: 192.168.10.0/24
        h1 = self.addHost("h1", ip="192.168.10.10/24", defaultRoute="via 192.168.10.1")
        
        # Subnet 2: 192.168.20.0/24 (Corporate cluster)
        h2 = self.addHost("h2", ip="192.168.20.10/24", defaultRoute="via 192.168.20.1")
        h3 = self.addHost("h3", ip="192.168.20.11/24", defaultRoute="via 192.168.20.1")
        h4 = self.addHost("h4", ip="192.168.20.12/24", defaultRoute="via 192.168.20.1")
        h5 = self.addHost("h5", ip="192.168.20.13/24", defaultRoute="via 192.168.20.1")
        
        # Subnet 3: 192.168.30.0/24
        h6 = self.addHost("h6", ip="192.168.30.10/24", defaultRoute="via 192.168.30.1")
        
        # Connect all hosts to the switch
        for h in [h1, h2, h3, h4, h5, h6]:
            self.addLink(h, s1)

def setup_mininet(controller_ip='127.0.0.1', controller_port=6653):
    """Create and start the Mininet network with 4-subnet topology."""
    logger.info("Setting up Mininet topology...")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    mininet_log_file = OUTPUT_DIR / "mininet.log"
    
    mininet_logger = logging.getLogger('mininet')
    mininet_logger.propagate = False
    mininet_logger.handlers = []
    
    file_handler = logging.FileHandler(mininet_log_file, mode='w')
    file_handler.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    mininet_logger.addHandler(file_handler)
    mininet_logger.addHandler(console_handler)
    mininet_logger.setLevel(logging.DEBUG)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    
    try:
        mn_version = subprocess.check_output(["mn", "--version"], universal_newlines=True).strip()
        logger.info(f"Mininet version: {mn_version}")
    except Exception as e:
        logger.warning(f"Could not get Mininet version: {e}")

    topo = ScenarioTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=True,
        build=False,
        cleanup=True
    )

    logger.info(f"Connecting to remote controller at {controller_ip}:{controller_port}")
    controller = RemoteController(
        'c0',
        ip=controller_ip,
        port=controller_port
    )
    net.addController(controller)

    net.build()
    net.start()

    logger.info("Mininet network started successfully.")
    
    # Allow time for L3 controller to learn topology and establish routing
    logger.info("Waiting for Layer 3 routing to stabilize...")
    time.sleep(15)
    
    # Test gateway connectivity
    logger.info("Testing gateway connectivity...")
    h1 = net.get('h1')
    h2 = net.get('h2')
    h6 = net.get('h6')
    
    # Quick gateway tests
    gw_tests = [
        (h1, '192.168.10.1', 'h1'),
        (h2, '192.168.20.1', 'h2')
    ]
    
    gateway_ok = True
    for host, gateway, name in gw_tests:
        result = host.cmd('ping -c1 192.168.10.1' if 'h1' in name else 'ping -c1 192.168.20.1')
        if '1 received' not in result:
            logger.warning(f"Gateway test failed for {name}")
            gateway_ok = False
    
    if gateway_ok:
        logger.info("Gateway connectivity: OK")
    else:
        logger.warning("Gateway connectivity tests failed")
    
    return net

def run_mininet_pingall_test(net):
    """Run Mininet's pingall test to verify basic connectivity."""
    logger.info("Running Mininet pingall test...")
    time.sleep(5)
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()

    original_mininet_log_level = logging.getLogger('mininet.log').level
    logging.getLogger('mininet.log').setLevel(logging.ERROR)

    try:
        result = net.pingAll()
    finally:
        sys.stdout = original_stdout
        logging.getLogger('mininet.log').setLevel(original_mininet_log_level)

    if result == 0.0:
        logger.info(f"Mininet pingall test completed successfully. Packet loss: {result}%")
    else:
        logger.error(f"Mininet pingall test failed. Packet loss: {result}%")

def start_capture(net, outfile, host=None):
    """Start tcpdump capture tailored for v4 192.168.0.0/16 topology.
    Captures full IPv4 packets within 192.168.0.0/16. If host is provided,
    capture on that host's primary interface; otherwise capture on switch s1.
    """
    logger.info(f"Starting packet capture. Output file: {outfile}")
    Path(outfile).parent.mkdir(parents=True, exist_ok=True)

    if host:
        node = net.get(host.name)
        intf = f"{host.name}-eth0"
        logger.info(f"Capturing on host {host.name} interface {intf}")
    else:
        node = net.get('s1')
        intf = 'any'
        logger.info(f"Capturing on switch s1 interface {intf}")

    cmd = [
        'tcpdump',
        '-i', intf,
        '-w', str(outfile),
        '-s', '0',
        'ip', 'and', 'not', 'ip6', 'and', 'net', '192.168.0.0/16'
    ]
    logger.info(f"Starting tcpdump with command: {' '.join(cmd)}")
    process = node.popen(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    time.sleep(2)
    if process.poll() is not None:
        error_output = process.stderr.read().strip()
        logger.error(f"tcpdump failed to start. Error: {error_output}")
        raise RuntimeError(f"tcpdump process exited with code {process.returncode}")
    logger.info(f"tcpdump started successfully with PID: {process.pid}")
    return process

def parse_flow_match_actions(match_str, actions_str):
    """Parses the match and actions strings from Ryu flow stats to extract specific fields."""
    in_port = None
    eth_src = None
    eth_dst = None
    out_port = None

    match_pattern = re.compile(r"'in_port': (\d+).*'eth_src': '([0-9a-fA-F:]+)'.*'eth_dst': '([0-9a-fA-F:]+)'")
    match_match = match_pattern.search(match_str)
    if match_match:
        in_port = int(match_match.group(1))
        eth_src = match_match.group(2)
        eth_dst = match_match.group(3)

    actions_pattern = re.compile(r"port=(\d+)")
    actions_match = actions_pattern.search(actions_str)
    if actions_match:
        out_port = int(actions_match.group(1))

    return in_port, eth_src, eth_dst, out_port

def update_flow_timeline(flow_label_timeline, label, start_time=None):
    """Update the flow label timeline with current phase information."""
    if start_time is None:
        start_time = time.time()
    
    if flow_label_timeline and 'end_time' not in flow_label_timeline[-1]:
        flow_label_timeline[-1]['end_time'] = start_time
    
    flow_label_timeline.append({
        'start_time': start_time,
        'label': label
    })
    logger.info(f"Timeline updated: {label} phase started at {start_time}")

def collect_flow_stats(duration, output_file, flow_label_timeline, stop_event=None, controller_ip='127.0.0.1', controller_port=8080, sync_start_time=None):
    """Collects flow statistics from the Ryu controller's REST API periodically and saves them to a CSV file."""
    logger.info(f"Starting flow statistics collection for {duration} seconds...")
    logger.info("Enhanced flow capture with 0.5s polling and flow timeout guarantees")
    flow_data = []
    start_time = sync_start_time if sync_start_time else time.time()
    api_url = f"http://{controller_ip}:{controller_port}/flows"

    poll_interval = 0.5
    next_poll = start_time
    empty_polls = 0
    
    total_polls = 0
    successful_polls = 0
    flows_captured = 0
    unique_flows = set()

    while time.time() - start_time < duration:
        if stop_event and stop_event.is_set():
            logger.info("Flow collection received stop signal, ending gracefully.")
            break
            
        current_time = time.time()
        if current_time < next_poll:
            time.sleep(next_poll - current_time)
            
        try:
            timestamp = time.time()
            
            response = requests.get(api_url, timeout=1.0)
            response.raise_for_status()
            flows = response.json()
            
            total_polls += 1
            next_poll += poll_interval
            label_multi = _get_label_for_timestamp(timestamp, flow_label_timeline)
            label_binary = 1 if label_multi != 'normal' else 0

            if flows:
                empty_polls = 0
                successful_polls += 1
                flows_captured += len(flows)
                for flow in flows:
                    flow_key = f"{flow.get('cookie', '')}-{flow.get('priority', '')}-{str(flow.get('match', ''))}"
                    unique_flows.add(flow_key)
                    in_port, eth_src, eth_dst, out_port = parse_flow_match_actions(flow.get('match', ''), flow.get('actions', ''))

                    flow_entry = {
                        'timestamp': timestamp,
                        'switch_id': flow.get('switch_id'),
                        'table_id': flow.get('table_id'),
                        'cookie': flow.get('cookie'),
                        'priority': flow.get('priority'),
                        'in_port': in_port,
                        'eth_src': eth_src,
                        'eth_dst': eth_dst,
                        'out_port': out_port,
                        'packet_count': flow.get('packet_count'),
                        'byte_count': flow.get('byte_count'),
                        'duration_sec': flow.get('duration_sec'),
                        'duration_nsec': flow.get('duration_nsec'),
                        'avg_pkt_size': 0,
                        'pkt_rate': 0,
                        'byte_rate': 0,
                        'Label_multi': label_multi,
                        'Label_binary': label_binary
                    }
                    
                    duration_sec = flow.get('duration_sec', 0)
                    duration_nsec = flow.get('duration_nsec', 0)
                    packet_count = flow.get('packet_count', 0)
                    byte_count = flow.get('byte_count', 0)

                    total_duration = duration_sec + (duration_nsec / 1_000_000_000)

                    if packet_count > 0:
                        flow_entry['avg_pkt_size'] = byte_count / packet_count
                    if total_duration > 0:
                        flow_entry['pkt_rate'] = packet_count / total_duration
                        flow_entry['byte_rate'] = byte_count / total_duration
                    
                    flow_data.append(flow_entry)
            else:
                empty_polls += 1
                flow_data.append({
                    'timestamp': timestamp,
                    'switch_id': None,
                    'table_id': None,
                    'cookie': None,
                    'priority': None,
                    'in_port': None,
                    'eth_src': None,
                    'eth_dst': None,
                    'out_port': None,
                    'packet_count': 0,
                    'byte_count': 0,
                    'duration_sec': 0,
                    'duration_nsec': 0,
                    'avg_pkt_size': 0,
                    'pkt_rate': 0,
                    'byte_rate': 0,
                    'Label_multi': label_multi,
                    'Label_binary': label_binary
                })
                if empty_polls % 30 == 0:
                    logger.debug(f"Flow stats empty for {empty_polls} consecutive polls during phase '{label_multi}'.")
        except requests.exceptions.RequestException as e:
            if stop_event and stop_event.is_set():
                logger.info("Flow collection received stop signal during error handling, ending gracefully.")
                break
            logger.error(f"Error collecting flow stats: {e}")
            time.sleep(5)
    
    if flow_label_timeline and 'end_time' not in flow_label_timeline[-1]:
        flow_label_timeline[-1]['end_time'] = time.time()
        logger.info("Flow timeline collection completed.")
    
    total_time = time.time() - start_time
    capture_rate = (successful_polls / total_polls * 100) if total_polls > 0 else 0
    avg_flows_per_poll = (flows_captured / successful_polls) if successful_polls > 0 else 0
    
    logger.info(f"=== Flow Capture Guarantee Report ===")
    logger.info(f"Total polling duration: {total_time:.2f}s")
    logger.info(f"Total polls attempted: {total_polls}")
    logger.info(f"Successful polls: {successful_polls} ({capture_rate:.1f}%)")
    logger.info(f"Total flow entries captured: {flows_captured}")
    logger.info(f"Unique flows tracked: {len(unique_flows)}")
    logger.info(f"Average flows per poll: {avg_flows_per_poll:.2f}")
    logger.info(f"Polling interval: {poll_interval}s (improved from 1.0s)")
    logger.info(f"Flow timeout settings: idle=30s, hard=300s")
    
    if flow_data:
        df = pd.DataFrame(flow_data)
        ordered_columns = [
            'timestamp', 'switch_id', 'table_id', 'cookie', 'priority',
            'in_port', 'eth_src', 'eth_dst', 'out_port',
            'packet_count', 'byte_count', 'duration_sec', 'duration_nsec',
            'avg_pkt_size', 'pkt_rate', 'byte_rate',
            'Label_multi', 'Label_binary'
        ]
        df = df.reindex(columns=ordered_columns)
        df.to_csv(output_file, index=False)
        logger.info(f"Flow statistics saved to {output_file.relative_to(BASE_DIR)}")
    else:
        logger.warning("No flow data collected.")

def stop_capture(process):
    """Stop the tcpdump process."""
    logger.info(f"Stopping packet capture (PID: {process.pid})...")
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        logger.warning(f"tcpdump (PID: {process.pid}) did not terminate gracefully. Forcing kill.")
        process.kill()
    logger.info("Packet capture stopped.")

def run_traffic_scenario(net, flow_label_timeline, scenario_durations, total_scenario_duration, config_file_path=None):
    """Orchestrate the traffic generation phases with DDoS attacks."""
    if not net:
        logger.error("Mininet network object is not valid. Aborting traffic scenario.")
        return

    logger.info("Starting traffic generation scenario...")
    
    if cpu_manager:
        cpu_manager.set_process_affinity('attacks')
        logger.info("[OK] Set CPU affinity for attack generation processes")
    
    phase_timings = {}
    scenario_start_time = time.time()

    capture_procs = {}
    flow_collector_thread = None
    flow_stop_event = threading.Event()

    try:
        phase_start = time.time()
        logger.info(f"Phase 1: Initialization ({scenario_durations['initialization']}s)...")
        time.sleep(scenario_durations['initialization'])
        phase_timings['initialization'] = time.time() - phase_start

        update_flow_timeline(flow_label_timeline, 'normal')

        flow_collector_thread = threading.Thread(
            target=collect_flow_stats,
            args=(total_scenario_duration, OUTPUT_FLOW_CSV_FILE, flow_label_timeline, flow_stop_event, '127.0.0.1', 8080, scenario_start_time)
        )
        flow_collector_thread.daemon = False
        flow_collector_thread.start()
        logger.info("Flow statistics collection started in background.")

        phase_start = time.time()
        logger.info(f"Phase 2: Normal Traffic ({scenario_durations['normal_traffic']}s)...")
        capture_procs['normal'] = start_capture(net, PCAP_FILE_NORMAL)
        time.sleep(0.5)
        run_benign_traffic(net, scenario_durations['normal_traffic'], OUTPUT_DIR, HOST_IPS)
        stop_capture(capture_procs['normal'])
        phase_timings['normal_traffic'] = time.time() - phase_start

        logger.info("Phase 3.1: Enhanced Traditional DDoS Attacks...")
        h1, h2, h4, h6 = net.get('h1', 'h2', 'h4', 'h6')

        phase_start = time.time()
        attack_logger.info(f"Attack: Enhanced SYN Flood ({scenario_durations['syn_flood']}s) | h1 -> h6")
        capture_procs['syn_flood'] = start_capture(net, PCAP_FILE_SYN_FLOOD)
        update_flow_timeline(flow_label_timeline, 'syn_flood')
        time.sleep(0.5)
        attack_proc_syn = run_syn_flood(h1, HOST_IPS['h6'], duration=scenario_durations['syn_flood'])
        attack_proc_syn.wait()
        stop_capture(capture_procs['syn_flood'])
        phase_timings['syn_flood'] = time.time() - phase_start
        attack_logger.info("Attack: Enhanced SYN Flood completed.")

        phase_start = time.time()
        attack_logger.info(f"Attack: Enhanced UDP Flood ({scenario_durations['udp_flood']}s) | h1 -> h6")
        capture_procs['udp_flood'] = start_capture(net, PCAP_FILE_UDP_FLOOD)
        update_flow_timeline(flow_label_timeline, 'udp_flood')
        time.sleep(0.5)
        attack_proc_udp = run_udp_flood(h1, HOST_IPS['h6'], duration=scenario_durations['udp_flood'])
        attack_proc_udp.wait()
        stop_capture(capture_procs['udp_flood'])
        phase_timings['udp_flood'] = time.time() - phase_start
        attack_logger.info("Attack: Enhanced UDP Flood completed.")

        phase_start = time.time()
        attack_logger.info(f"Attack: Enhanced ICMP Flood ({scenario_durations['icmp_flood']}s) | h1 -> h4")
        capture_procs['icmp_flood'] = start_capture(net, PCAP_FILE_ICMP_FLOOD)
        update_flow_timeline(flow_label_timeline, 'icmp_flood')
        time.sleep(0.5)
        attack_proc_icmp = run_icmp_flood(h1, HOST_IPS['h4'], duration=scenario_durations['icmp_flood'])
        attack_proc_icmp.wait()
        stop_capture(capture_procs['icmp_flood'])
        phase_timings['icmp_flood'] = time.time() - phase_start
        attack_logger.info("Attack: Enhanced ICMP Flood completed.")

        logger.info("Phase 3.2: DDoS Attack Generation completed.")



        if flow_collector_thread and flow_collector_thread.is_alive():
            logger.info("Signaling flow collection thread to stop before cooldown...")
            flow_stop_event.set()
            logger.info("Waiting for flow collection thread to finish...")
            flow_collector_thread.join(timeout=30)
            if flow_collector_thread.is_alive():
                logger.warning("Flow collection thread did not finish within timeout")
            else:
                logger.info("Flow collection thread finished successfully")

        phase_start = time.time()
        logger.info(f"Phase 4: Cooldown ({scenario_durations['cooldown']}s)...")
        logger.info("Note: Flow collection stopped before cooldown to ensure dataset consistency")
        time.sleep(scenario_durations['cooldown'])
        phase_timings['cooldown'] = time.time() - phase_start

    except Exception as e:
        logger.error(f"An error occurred during traffic scenario: {e}", exc_info=True)
    finally:
        for proc_name, proc in capture_procs.items():
            if proc and proc.poll() is None:
                logger.warning(f"Capture process for {proc_name} was still running. Stopping it.")
                stop_capture(proc)

        if flow_collector_thread and flow_collector_thread.is_alive():
            logger.warning("Flow collection thread still running - stopping as cleanup...")
            flow_stop_event.set()
            flow_collector_thread.join(timeout=30)
            if flow_collector_thread.is_alive():
                logger.warning("Flow collection thread did not finish within timeout during cleanup")
            else:
                logger.info("Flow collection thread finished during cleanup")
        
        total_scenario_time = time.time() - scenario_start_time
        
        logger.info("=" * 60)
        logger.info("FEATURE TIMING SUMMARY (4-Subnet Topology)")
        logger.info("=" * 60)
        if config_file_path:
            logger.info(f"Configuration File: {config_file_path}")
            logger.info("")
        logger.info(f"Total Scenario Runtime: {total_scenario_time:.2f} seconds ({total_scenario_time/60:.2f} minutes)")
        logger.info("")
        logger.info("Phase-by-Phase Breakdown:")
        
        # Enhanced Traditional attacks
        logger.info("  Enhanced Traditional Attacks:")
        for attack in ['syn_flood', 'udp_flood', 'icmp_flood']:
            if attack in phase_timings:
                enhanced_name = f"Enhanced {attack.replace('_', ' ').title()}"
                logger.info(f"    {enhanced_name}: {phase_timings[attack]:.2f}s (configured: {scenario_durations.get(attack, 'N/A')}s)")
        
        
        # Other phases
        for phase in ['initialization', 'normal_traffic', 'cooldown']:
            if phase in phase_timings:
                logger.info(f"  {phase.title()}: {phase_timings[phase]:.2f}s (configured: {scenario_durations.get(phase, 'N/A')}s)")
        
        logger.info("=" * 60)
        logger.info("Traffic generation scenario finished.")

def cleanup(controller_proc, mininet_running):
    """Clean up all running processes and network configurations."""
    logger.info("Cleaning up resources...")
    if controller_proc:
        logger.info(f"Terminating Ryu controller (PID: {controller_proc.pid})...")
        controller_proc.terminate()
        controller_proc.wait()

    logger.info("Cleaning up Mininet environment...")
    cleanup_cmd = ["mn", "-c"]
    subprocess.run(cleanup_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    logger.info("Cleanup complete.")

def process_single_pcap_30_features(pcap_file_path, label_name, output_dir, master_timeline=None):
    import pandas as pd
    from pathlib import Path
    import logging
    import time
    import traceback
    import os
    from src.utils.process_pcap_to_csv import _get_label_for_timestamp
    
    worker_logger = logging.getLogger(f'worker_{label_name}')
    worker_logger.setLevel(logging.INFO)
    
    pcap_file = Path(pcap_file_path)
    output_dir = Path(output_dir)
    
    try:
        worker_logger.info(f"=== STARTING PCAP PROCESSING DEBUG ===")
        worker_logger.info(f"Processing {pcap_file.name} with label '{label_name}' for 30 features...")
        worker_logger.info(f"PCAP file path: {pcap_file}")
        worker_logger.info(f"Output directory: {output_dir}")
        worker_logger.info(f"Master timeline provided: {master_timeline is not None}")
        
        worker_logger.info("Step 1: Checking file existence and permissions...")
        if not pcap_file.exists():
            worker_logger.error(f"PCAP file not found: {pcap_file}")
            worker_logger.error(f"File path absolute: {pcap_file.is_absolute()}")
            worker_logger.error(f"Parent directory exists: {pcap_file.parent.exists()}")
            return None
        
        try:
            file_stats = os.stat(pcap_file)
            worker_logger.info(f"File size: {file_stats.st_size} bytes")
            worker_logger.info(f"File permissions: {oct(file_stats.st_mode)}")
            worker_logger.info(f"File readable: {os.access(pcap_file, os.R_OK)}")
        except Exception as perm_e:
            worker_logger.error(f"Error checking file permissions: {perm_e}")
            worker_logger.error(f"Permission check traceback: {traceback.format_exc()}")

        worker_logger.info("Step 2: Validating import dependencies...")
        try:
            from src.utils.enhanced_pcap_processing import verify_pcap_integrity, validate_and_fix_pcap_timestamps
            worker_logger.info("[OK] Enhanced PCAP processing imports successful")
        except ImportError as import_e:
            worker_logger.error(f"[FAIL] Import error for enhanced PCAP processing: {import_e}")
            worker_logger.error(f"Import traceback: {traceback.format_exc()}")
            return None

        worker_logger.info("Step 3: Running PCAP integrity check...")
        try:
            integrity_results = verify_pcap_integrity(pcap_file)
            if not integrity_results['valid']:
                worker_logger.error(f"PCAP integrity check failed for {pcap_file.name}: {integrity_results['error']}")
                worker_logger.error(f"Integrity details: {integrity_results}")
                worker_logger.warning("Continuing with PCAP processing despite integrity issues...")
            else:
                worker_logger.info(f"[OK] PCAP integrity check passed for {pcap_file.name}: {integrity_results['total_packets']} packets")
        except Exception as integrity_e:
            worker_logger.error(f"[FAIL] Error during PCAP integrity check: {integrity_e}")
            worker_logger.error(f"Integrity check traceback: {traceback.format_exc()}")
            return None

        worker_logger.info("Step 4: Processing PCAP timestamps...")
        try:
            corrected_packets, stats = validate_and_fix_pcap_timestamps(pcap_file)
            pcap_start_time = stats['baseline_time']
            worker_logger.info(f"[OK] Using baseline timestamp for labeling {pcap_file.name}: {pcap_start_time}")
            worker_logger.info(f"Timestamp stats: {stats}")
        except Exception as timestamp_e:
            worker_logger.error(f"[FAIL] Could not process PCAP timestamps for {pcap_file}: {timestamp_e}")
            worker_logger.error(f"Timestamp processing traceback: {traceback.format_exc()}")
            return None

        worker_logger.info("Step 5: Setting up timeline for consistent labeling...")
        time_offset = 0.0
        if master_timeline and len(master_timeline) > 0:
            matching_entries = [e for e in master_timeline if e.get('label') == label_name]
            if matching_entries:
                label_timeline = master_timeline
                phase_start = matching_entries[0].get('start_time', pcap_start_time)
                time_offset = float(phase_start) - float(pcap_start_time)
                worker_logger.info(f"[OK] Using master timeline with {len(label_timeline)} phases for consistent labeling")
                worker_logger.info(f"Master timeline phase for '{label_name}' starts at {phase_start}")
                worker_logger.info(f"PCAP first packet time (baseline): {pcap_start_time}")
                worker_logger.info(f"Computed time offset: {time_offset:.6f} seconds")
            else:
                worker_logger.warning(f"Master timeline does not contain label '{label_name}'. Falling back to single-label timeline.")
                label_timeline = [{
                    'start_time': pcap_start_time,
                    'end_time': pcap_start_time + 3600,
                    'label': label_name
                }]
                worker_logger.info(f"[OK] Created fallback single-label timeline: {label_timeline}")
        else:
            label_timeline = [{
                'start_time': pcap_start_time,
                'end_time': pcap_start_time + 3600,
                'label': label_name
            }]
            worker_logger.info(f"[OK] Created fallback single-label timeline: {label_timeline}")
        
        worker_logger.info("Step 6: Setting up temporary CSV file...")
        temp_csv_file = output_dir / f"temp_{label_name}_30.csv"
        worker_logger.info(f"Temporary CSV path: {temp_csv_file}")
        
        try:
            if not output_dir.exists():
                worker_logger.error(f"[FAIL] Output directory does not exist: {output_dir}")
                return None
            if not os.access(output_dir, os.W_OK):
                worker_logger.error(f"[FAIL] Output directory is not writable: {output_dir}")
                return None
            worker_logger.info(f"[OK] Output directory is writable")
        except Exception as dir_e:
            worker_logger.error(f"[FAIL] Error checking output directory: {dir_e}")
            worker_logger.error(f"Directory check traceback: {traceback.format_exc()}")
            return None
        
        worker_logger.info("Step 7: Starting core PCAP to CSV processing...")
        try:
            result = process_pcap_to_30_features_csv(
                str(pcap_file), 
                str(temp_csv_file), 
                label_timeline,
                worker_logger,
                time_offset
            )
            
            if result is None:
                worker_logger.error(f"[FAIL] process_pcap_to_30_features_csv returned None for {pcap_file.name}")
                if master_timeline and len(master_timeline) > 0:
                    worker_logger.warning("Retrying with fallback single-label timeline and zero offset...")
                    fallback_timeline = [{
                        'start_time': pcap_start_time,
                        'end_time': pcap_start_time + 3600,
                        'label': label_name
                    }]
                    try:
                        result = process_pcap_to_30_features_csv(
                            str(pcap_file),
                            str(temp_csv_file),
                            fallback_timeline,
                            worker_logger,
                            0.0
                        )
                    except Exception:
                        result = None

                if result is None:
                    return None
            else:
                worker_logger.info(f"[OK] Core PCAP processing completed successfully")
            
        except Exception as processing_e:
            worker_logger.error(f"[FAIL] Error in core PCAP processing: {processing_e}")
            worker_logger.error(f"Core processing traceback: {traceback.format_exc()}")
            return None
        
        worker_logger.info("Step 8: Validating CSV output...")
        if temp_csv_file.exists():
            worker_logger.info(f"[OK] Temporary CSV file created: {temp_csv_file}")
            try:
                df = pd.read_csv(temp_csv_file)
                worker_logger.info(f"[OK] CSV loaded successfully: {len(df)} rows, {len(df.columns)} columns")
                worker_logger.info(f"CSV columns: {list(df.columns)}")
                temp_csv_file.unlink()
                worker_logger.info(f"[OK] Temporary CSV file cleaned up")
                worker_logger.info(f"=== SUCCESSFULLY PROCESSED {pcap_file.name} ===")
                return df
            except Exception as csv_e:
                worker_logger.error(f"[FAIL] Error reading CSV file: {csv_e}")
                worker_logger.error(f"CSV reading traceback: {traceback.format_exc()}")
                return None
        else:
            worker_logger.error(f"[FAIL] No CSV generated for {pcap_file.name}.")
            worker_logger.error(f"Expected CSV path: {temp_csv_file}")
            worker_logger.error(f"Output directory contents: {list(output_dir.iterdir())}")
            return None
            
    except Exception as e:
        worker_logger.error(f"[FAIL] CRITICAL ERROR processing {pcap_file.name}: {e}")
        worker_logger.error(f"Full error traceback: {traceback.format_exc()}")
        worker_logger.error(f"Error type: {type(e).__name__}")
        worker_logger.error(f"=== FAILED TO PROCESS {pcap_file.name} ===")
        return None

def process_pcaps_parallel_30_features(pcap_files_to_process, output_dir, max_workers=6, master_timeline=None):
    """Process multiple PCAP files in parallel using multiprocessing with CPU affinity for 30 features."""
    import traceback
    
    logger.info(f"=== PARALLEL PCAP PROCESSING START ===")
    logger.info(f"Files to process: {len(pcap_files_to_process)}")
    logger.info(f"Max workers: {max_workers}")
    logger.info(f"Output directory: {output_dir}")
    
    for pcap_file, label_name in pcap_files_to_process:
        logger.info(f"  - {pcap_file.name} -> {label_name}")
    
    if cpu_manager:
        cpu_manager.set_process_affinity('pcap')
        logger.info("[OK] Set CPU affinity for PCAP processing (all cores)")
    
    all_labeled_dfs = []
    processing_results = {}
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_pcap = {}
        
        logger.info("Submitting processing jobs...")
        for pcap_file, label_name in pcap_files_to_process:
            try:
                future = executor.submit(process_single_pcap_30_features, str(pcap_file), label_name, str(output_dir), master_timeline)
                future_to_pcap[future] = (pcap_file, label_name)
                logger.info(f"[OK] Submitted job for {pcap_file.name}")
            except Exception as submit_e:
                logger.error(f"[FAIL] Error submitting job for {pcap_file.name}: {submit_e}")
                logger.error(f"Submit error traceback: {traceback.format_exc()}")
                processing_results[pcap_file.name] = {'status': 'SUBMIT_FAILED', 'error': str(submit_e)}
        
        logger.info(f"Processing {len(future_to_pcap)} submitted jobs...")
        
        for future in future_to_pcap:
            pcap_file, label_name = future_to_pcap[future]
            pcap_name = pcap_file.name
            
            try:
                logger.info(f"Waiting for result from {pcap_name}...")
                df = future.result(timeout=300)  # 5 minute timeout per file
                
                if df is not None and not df.empty:
                    all_labeled_dfs.append(df)
                    processing_results[pcap_name] = {'status': 'SUCCESS', 'rows': len(df), 'cols': len(df.columns)}
                    logger.info(f"[OK] Completed processing {pcap_name} ({len(df)} records with {len(df.columns)} features)")
                else:
                    processing_results[pcap_name] = {'status': 'EMPTY_RESULT', 'error': 'DataFrame is None or empty'}
                    logger.error(f"[FAIL] Failed to process {pcap_name} - empty result")
                    
            except Exception as result_e:
                processing_results[pcap_name] = {'status': 'RESULT_ERROR', 'error': str(result_e)}
                logger.error(f"[FAIL] Error processing {pcap_name}: {result_e}")
                logger.error(f"Error type: {type(result_e).__name__}")
                logger.error(f"Result error traceback: {traceback.format_exc()}")
    
    logger.info(f"=== PARALLEL PROCESSING SUMMARY ===")
    logger.info(f"Total files submitted: {len(pcap_files_to_process)}")
    logger.info(f"Successful processing: {len(all_labeled_dfs)}")
    logger.info(f"Failed processing: {len(pcap_files_to_process) - len(all_labeled_dfs)}")
    
    logger.info("Individual file results:")
    for pcap_file, label_name in pcap_files_to_process:
        pcap_name = pcap_file.name
        if pcap_name in processing_results:
            result = processing_results[pcap_name]
            status = result['status']
            
            if status == 'SUCCESS':
                logger.info(f"  [OK] {pcap_name}: SUCCESS ({result['rows']} rows)")
            else:
                logger.info(f"  [FAIL] {pcap_name}: {status} - {result.get('error', 'Unknown error')}")
        else:
            logger.info(f"  ? {pcap_name}: NO RESULT RECORDED")
    
    if len(all_labeled_dfs) == 0:
        logger.error("[FAIL] NO FILES PROCESSED SUCCESSFULLY - All PCAP processing failed!")
        logger.error("Check individual file processing logs above for specific errors.")
    else:
        logger.info(f"[OK] Parallel PCAP processing completed. {len(all_labeled_dfs)} files processed successfully.")
    
    logger.info(f"=== PARALLEL PCAP PROCESSING END ===")
    return all_labeled_dfs

def check_cicflowmeter():
    """Check if CICFlowMeter is installed and accessible"""
    try:
        result = subprocess.run(['cicflowmeter', '--help'],
                              capture_output=True, text=True, timeout=10)
        logger.info("CICFlowMeter is available")
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        logger.warning("CICFlowMeter not found. Install with: pip install cicflowmeter")
        return False

def extract_cicflow_features_from_pcap(pcap_file, attack_type, output_dir=None):
    """Extract CICFlow features from a single PCAP file"""
    if isinstance(pcap_file, str):
        pcap_file = Path(pcap_file)

    if output_dir is None:
        output_dir = OUTPUT_DIR

    temp_output = output_dir / f"temp_{pcap_file.stem}_cicflows.csv"

    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return None

    logger.info(f"Processing {pcap_file.name} with CICFlowMeter...")

    # Label mappings for CICFlow (updated for 4 attack types)
    multi_labels = {
        'normal': 'normal',
        'syn_flood': 'syn_flood',
        'udp_flood': 'udp_flood',
        'icmp_flood': 'icmp_flood'
    }

    binary_labels = {
        'normal': 0,
        'syn_flood': 1,
        'udp_flood': 1,
        'icmp_flood': 1
    }

    try:
        # Run CICFlowMeter
        cmd = [
            'cicflowmeter',
            '-f', str(pcap_file),
            '-c', str(temp_output)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            logger.error(f"CICFlowMeter failed for {pcap_file.name}: {result.stderr}")
            return None

        # Check if output file was created
        if not temp_output.exists():
            logger.error(f"No CICFlow output file generated for {pcap_file.name}")
            return None

        # Read the generated CSV
        try:
            df = pd.read_csv(temp_output)
            if len(df) == 0:
                logger.warning(f"No CICFlow flows found in output for {pcap_file.name}")
                temp_output.unlink()
                return None

            # Add labels
            df = df.copy()
            df['Label_multi'] = multi_labels[attack_type]
            df['Label_binary'] = binary_labels[attack_type]

            logger.info(f"Extracted {len(df)} CICFlow flows from {pcap_file.name}")

        except pd.errors.EmptyDataError:
            logger.warning(f"CICFlowMeter generated empty output for {pcap_file.name}")
            temp_output.unlink()
            return None
        except Exception as e:
            logger.error(f"Error reading CICFlowMeter output for {pcap_file.name}: {e}")
            if temp_output.exists():
                temp_output.unlink()
            return None

        # Clean up temporary file
        temp_output.unlink()

        return df

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout processing {pcap_file.name} with CICFlowMeter")
        return None
    except Exception as e:
        logger.error(f"Error processing {pcap_file.name} with CICFlowMeter: {e}")
        return None

def process_cicflow_features(pcap_files_to_process, output_dir=None):
    """Process all PCAP files with CICFlowMeter and combine into labeled dataset"""
    if output_dir is None:
        output_dir = OUTPUT_DIR

    logger.info("=== STARTING CICFLOW FEATURE EXTRACTION ===")

    # Check CICFlowMeter availability
    if not check_cicflowmeter():
        logger.error("CICFlowMeter not available. Skipping CICFlow feature extraction.")
        return None

    all_cicflow_dfs = []
    processing_results = {}

    for pcap_file, label_name in pcap_files_to_process:
        try:
            logger.info(f"Processing {pcap_file.name} for CICFlow features...")

            df = extract_cicflow_features_from_pcap(pcap_file, label_name, output_dir)

            if df is not None and not df.empty:
                all_cicflow_dfs.append(df)
                processing_results[pcap_file.name] = {'status': 'SUCCESS', 'rows': len(df), 'cols': len(df.columns)}
                logger.info(f"[OK] Completed CICFlow processing {pcap_file.name} ({len(df)} flows with {len(df.columns)} features)")
            else:
                processing_results[pcap_file.name] = {'status': 'EMPTY_RESULT', 'error': 'DataFrame is None or empty'}
                logger.error(f"[FAIL] Failed CICFlow processing {pcap_file.name} - empty result")

        except Exception as e:
            processing_results[pcap_file.name] = {'status': 'ERROR', 'error': str(e)}
            logger.error(f"[FAIL] Error in CICFlow processing {pcap_file.name}: {e}")

    logger.info(f"=== CICFLOW PROCESSING SUMMARY ===")
    for pcap_name, result in processing_results.items():
        status = result['status']
        if status == 'SUCCESS':
            logger.info(f"  [OK] {pcap_name}: {result['rows']} flows, {result['cols']} features")
        else:
            logger.info(f"  [FAIL] {pcap_name}: {status} - {result.get('error', 'Unknown error')}")

    if len(all_cicflow_dfs) == 0:
        logger.error("[FAIL] NO CICFLOW FILES PROCESSED SUCCESSFULLY")
        return None
    else:
        logger.info(f"[OK] CICFlow processing completed. {len(all_cicflow_dfs)} files processed successfully.")

    # Combine all dataframes
    try:
        combined_df = pd.concat(all_cicflow_dfs, ignore_index=True)
        logger.info(f"[OK] Combined CICFlow dataset: {len(combined_df)} flows, {len(combined_df.columns)} features")
        return combined_df

    except Exception as e:
        logger.error(f"[FAIL] Error combining CICFlow dataframes: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="UKMDDoSDN v1.0 Dataset Generation")
    parser.add_argument(
        'config_file', 
        nargs='?', 
        default='config.json',
        help='Path to configuration JSON file (default: config.json)'
    )
    parser.add_argument('--cores', type=int, default=min(4, cpu_count()), 
                       help=f'Number of CPU cores to use for PCAP processing (default: {min(4, cpu_count())}, max: {cpu_count()})')
    parser.add_argument('--max-cores', type=int, default=16,
                       help='Maximum number of CPU cores available for optimal allocation (default: 16)')
    parser.add_argument('--controller-ip', type=str, default='127.0.0.1',
                       help='IP address the switch uses to connect to the controller (default: 127.0.0.1). Set to 192.168.0.1 to use v4 mgmt subnet.')
    parser.add_argument('--controller-port', type=int, default=6653,
                       help='OpenFlow port for the controller (default: 6653)')
    parser.add_argument('--controller-rest-host', type=str, default='localhost',
                       help='Host/IP to use when checking the controller REST API (default: localhost)')
    parser.add_argument('--disable-cpu-affinity', action='store_true',
                       help='Disable CPU affinity optimization (default: enabled with auto-detection)')
    args = parser.parse_args()

    global cpu_manager, logger
    for handler in list(logger.handlers):
        logger.removeHandler(handler)


    # Ensure logging is initialized before any log messages
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    initialize_logging(OUTPUT_DIR, console_level=logging.INFO)
    logger = get_main_logger(OUTPUT_DIR)

    main_start_time = time.time()

    actual_cpu_count = cpu_count()

    if args.disable_cpu_affinity:
        cpu_manager = None
        logger.info(f"[TOOLS] CPU Affinity Optimization DISABLED (user requested)")
    else:
        effective_cores = min(args.max_cores, actual_cpu_count)

        if args.max_cores > actual_cpu_count:
            logger.warning(f"[WARN]  Requested max cores ({args.max_cores}) exceeds system CPU count ({actual_cpu_count})")
            logger.warning(f"[WARN]  Using {effective_cores} cores for CPU affinity optimization")

        cpu_manager = CPUCoreManager(total_cores=effective_cores)

    
    ConsoleOutput.print_header("UKMDDoSDN v1.0 Dataset Generation Framework")
    logger.info("[NETWORK] 4-Subnet Enterprise Topology with Layer 3 Routing")
    logger.info("[GLOBAL] Network Configuration:")
    logger.info("   - h1: 192.168.10.0/24 (Isolated/External Network)")
    logger.info("   - h2-h5: 192.168.20.0/24 (Corporate Internal Network)")
    logger.info("   - h6: 192.168.30.0/24 (Server/DMZ Network)")
    logger.info("   - Controller: 192.168.0.0/24 (Management Network)")
    if cpu_manager:
        logger.info(f"[TOOLS] CPU Affinity Optimization ENABLED (using {cpu_manager.total_cores}/{actual_cpu_count} cores)")
        cpu_manager.print_allocation()
    else:
        logger.info("[TOOLS] CPU Affinity Optimization DISABLED")

    logger.info("Cleaning up any previous Mininet instances...")
    subprocess.run(["mn", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logger.info("Mininet cleanup complete.")

    verify_tools()

    config_file_path = Path(args.config_file)
    if not config_file_path.is_absolute():
        config_file_path = BASE_DIR / config_file_path
    
    if not config_file_path.exists():
        logger.error(f"Config file not found: {config_file_path}")
        sys.exit(1)
    
    logger.info(f"Using configuration file: {config_file_path}")
    with open(config_file_path, 'r') as f:
        config = json.load(f)
    
    scenario_durations = config.get("scenario_durations", {})
    
    initialization_duration = scenario_durations.get("initialization", 5)
    normal_traffic_duration = scenario_durations.get("normal_traffic", 5)
    syn_flood_duration = scenario_durations.get("syn_flood", 5)
    udp_flood_duration = scenario_durations.get("udp_flood", 5)
    icmp_flood_duration = scenario_durations.get("icmp_flood", 5)
    cooldown_duration = scenario_durations.get("cooldown", 10)

    controller_process = None
    mininet_network = None
    
    try:
        controller_process = start_controller()
        if not check_controller_health(port=args.controller_port):
            raise RuntimeError("Controller health check failed. Aborting.")

        logger.info("Testing /hello endpoint...")
        try:
            import requests
            response = requests.get(f"http://{args.controller_rest_host}:8080/hello", timeout=10)
            
            if response.status_code == 200:
                try:
                    response_json = response.json()
                    if response_json.get("message") == "Hello from Ryu L3 Router Controller!":
                        logger.info("Test /hello endpoint: PASSED")
                    else:
                        logger.info("Test /hello endpoint: PASSED (controller responding but different message)")
                except ValueError:
                    logger.info("Test /hello endpoint: PASSED (controller responding)")
            else:
                logger.warning(f"Test /hello endpoint: HTTP {response.status_code} - continuing anyway")
                
        except requests.exceptions.ConnectionError:
            logger.warning("Test /hello endpoint: REST API not accessible - continuing anyway")
        except Exception as e:
            logger.warning(f"Test /hello endpoint: {e} - continuing anyway")

        mininet_network = setup_mininet(controller_ip=args.controller_ip, controller_port=args.controller_port)

        run_mininet_pingall_test(mininet_network)

        scenario_start_time = time.time()

        flow_label_timeline = []
        
        config_duration = normal_traffic_duration + syn_flood_duration + udp_flood_duration + icmp_flood_duration + \
                         cooldown_duration
        total_scenario_duration = config_duration + 120

        run_traffic_scenario(mininet_network, flow_label_timeline, scenario_durations, total_scenario_duration, config_file_path)

        logger.info("PCAP generation complete.")

        pcap_files_to_process = [
            (PCAP_FILE_NORMAL, 'normal'),
            (PCAP_FILE_SYN_FLOOD, 'syn_flood'),
            (PCAP_FILE_UDP_FLOOD, 'udp_flood'),
            (PCAP_FILE_ICMP_FLOOD, 'icmp_flood'),
        ]

        max_workers = min(max(1, args.cores), cpu_count())
        if args.cores > cpu_count():
            logger.warning(f"Requested {args.cores} cores, but only {cpu_count()} available. Using {max_workers} cores.")
        
        # Generate all datasets using the refactored dataset generator
        from src.dataset_generator import generate_all_datasets, print_generation_summary

        logger.info("Generating all datasets (packet, flow, and CICFlow features)...")
        generation_start_time = time.time()

        dataset_results = generate_all_datasets(
            pcap_files_to_process,
            OUTPUT_DIR,
            OUTPUT_CSV_FILE,
            OUTPUT_FLOW_CSV_FILE,
            OUTPUT_CICFLOW_CSV_FILE,
            flow_label_timeline,
            max_workers,
            process_pcaps_parallel_30_features,
            process_cicflow_features,
            logger
        )

        generation_time = time.time() - generation_start_time
        logger.info(f"Total dataset generation completed in {generation_time:.2f} seconds ({generation_time/60:.2f} minutes)")

        print_generation_summary(dataset_results, logger)

        logger.info("Generating dataset summary...")
        print_dataset_summary(OUTPUT_DIR, logger)
        
        # Run timeline analysis if both packet and flow datasets were generated successfully
        if dataset_results['packet']['success'] and dataset_results['flow']['success']:
            logger.info("Running timeline analysis...")
            timeline_results = analyze_dataset_timeline(OUTPUT_CSV_FILE, OUTPUT_FLOW_CSV_FILE, logger)

            if timeline_results['score'] < 70:
                print_detailed_timeline_report(timeline_results, logger)

            timeline_score = timeline_results['score']
            timeline_status = timeline_results['status']
        else:
            logger.warning("Skipping timeline analysis - packet or flow dataset generation failed")
            timeline_score = 0
            timeline_status = "GENERATION_FAILED"
        
        total_execution_time = time.time() - main_start_time
        logger.info("=" * 80)
        logger.info("FEATURE FINAL EXECUTION SUMMARY (4-SUBNET TOPOLOGY)")
        logger.info("=" * 80)
        logger.info(f"[RUN] Framework Version: v1.0")
        logger.info(f"[STATS] Generated Datasets: {sum(1 for r in dataset_results.values() if r['success'])}/3 (Packet, Flow, CICFlow)")
        logger.info(f"[TARGET] Target Latency: <1ms per packet extraction")
        if cpu_manager:
            logger.info(f"[POWER] CPU Affinity Optimization: ENABLED ({cpu_manager.total_cores}/{actual_cpu_count} cores)")
        else:
            logger.info(f"[POWER] CPU Affinity Optimization: DISABLED")
        logger.info(f"[DESKTOP]  Total Cores Available: {actual_cpu_count}")
        logger.info(f"[TIME]  Total Execution Time: {total_execution_time:.2f} seconds ({total_execution_time/60:.2f} minutes | {total_execution_time/3600:.2f} hours)")
        logger.info(f"[DATE] Dataset Generation Complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if 'timeline_score' in locals():
            logger.info(f"[CHART] Timeline Alignment Score: {timeline_score:.1f}%")
            if timeline_score >= 90:
                logger.info("[OK] Timeline Quality: EXCELLENT")
            elif timeline_score >= 70:
                logger.info("[OK] Timeline Quality: GOOD")
            elif timeline_score >= 50:
                logger.info("[WARN]  Timeline Quality: FAIR - Consider adjustments")
            else:
                logger.info("[FAIL] Timeline Quality: POOR - Requires attention")
        
        logger.info("=" * 80)
        logger.info("[DONE] v1.0 MULTI-DATASET DDOS DETECTION FRAMEWORK COMPLETED (4-SUBNET TOPOLOGY)")
        logger.info("[NOTES] Generated Datasets:")
        logger.info("   - Packet Dataset: 30-feature real-time optimized features")
        logger.info("   - Flow Dataset: SDN controller-based flow statistics")
        logger.info("   - CICFlow Dataset: CICFlowMeter-based flow features")
        logger.info("   - 2 Labels per dataset: multi-class + binary classification")
        logger.info("   - Timeline-ordered for ML training compatibility")
        logger.info("   - Optimized for production real-time deployment")
        logger.info("[NETWORK] 4-Subnet Enterprise Network Topology:")
        logger.info("   - Inter-subnet attack scenarios (cross-network DDoS)")
        logger.info("   - Realistic enterprise network segmentation")
        logger.info("   - Layer 3 routing with SDN controller")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        cleanup(controller_process, mininet_network is not None)

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("This script must be run as root for Mininet.")
        sys.exit(1)
    main()


