"""
Enhanced Timing Module for Traditional DDoS Attacks

This module provides human-like timing patterns that simulate realistic
network behavior patterns for traditional attack enhancement.
"""

import time
import random
import math
import logging

# Get the centralized attack logger
attack_logger = logging.getLogger('attack_logger')


class HumanLikeTiming:
    """Simulates human-like timing patterns for more realistic attacks."""
    
    def __init__(self):
        """Initialize timing patterns based on human behavior studies."""
        # Human typing patterns (inter-keystroke intervals in seconds)
        self.typing_intervals = [0.08, 0.12, 0.15, 0.09, 0.11, 0.13, 0.10, 0.14]
        
        # Mouse click patterns (time between clicks)
        self.click_intervals = [0.2, 0.3, 0.25, 0.35, 0.4, 0.28, 0.32, 0.38]
        
        # Network think time (time between requests)
        self.think_times = [1.0, 1.5, 2.0, 0.8, 1.2, 1.8, 2.5, 3.0]
        
        # Circadian rhythm factors (0.0-1.0, where 1.0 is peak activity)
        self.hourly_activity = {
            0: 0.1, 1: 0.05, 2: 0.03, 3: 0.02, 4: 0.02, 5: 0.05,
            6: 0.1, 7: 0.2, 8: 0.4, 9: 0.7, 10: 0.8, 11: 0.9,
            12: 0.85, 13: 0.8, 14: 0.9, 15: 0.95, 16: 0.9, 17: 0.8,
            18: 0.7, 19: 0.6, 20: 0.5, 21: 0.4, 22: 0.3, 23: 0.2
        }
    
    def get_typing_interval(self):
        """Get a realistic typing interval with natural variation."""
        base_interval = random.choice(self.typing_intervals)
        # Add natural variation (30%)
        variation = random.uniform(-0.3, 0.3)
        return max(0.05, base_interval * (1 + variation))
    
    def get_click_interval(self):
        """Get a realistic mouse click interval."""
        base_interval = random.choice(self.click_intervals)
        # Add natural variation (25%)
        variation = random.uniform(-0.25, 0.25)
        return max(0.1, base_interval * (1 + variation))
    
    def get_think_time(self):
        """Get a realistic think time between actions."""
        base_time = random.choice(self.think_times)
        # Add significant variation for think time (50%)
        variation = random.uniform(-0.5, 0.5)
        return max(0.5, base_time * (1 + variation))
    
    def get_circadian_factor(self, hour=None):
        """Get activity factor based on time of day."""
        if hour is None:
            hour = time.localtime().tm_hour
        return self.hourly_activity.get(hour, 0.5)
    
    def get_human_like_interval(self, action_type="typing"):
        """
        Get a human-like interval based on action type.
        
        Args:
            action_type: Type of action ("typing", "clicking", "thinking")
            
        Returns:
            float: Interval in seconds
        """
        if action_type == "typing":
            return self.get_typing_interval()
        elif action_type == "clicking":
            return self.get_click_interval()
        elif action_type == "thinking":
            return self.get_think_time()
        else:
            # Default to typing pattern
            return self.get_typing_interval()
    
    def get_session_pattern(self, duration_minutes=10):
        """
        Generate a realistic session pattern with breaks and intensity changes.
        
        Args:
            duration_minutes: Total session duration
            
        Returns:
            list: List of (interval, intensity) tuples
        """
        pattern = []
        total_seconds = duration_minutes * 60
        current_time = 0
        
        while current_time < total_seconds:
            # Session phases: active (80%), break (20%)
            if random.random() < 0.8:
                # Active phase (30-180 seconds)
                phase_duration = random.uniform(30, 180)
                intensity = random.uniform(0.7, 1.0)
                phase_type = "active"
            else:
                # Break phase (5-30 seconds)
                phase_duration = random.uniform(5, 30)
                intensity = random.uniform(0.1, 0.3)
                phase_type = "break"
            
            # Don't exceed total duration
            phase_duration = min(phase_duration, total_seconds - current_time)
            
            pattern.append({
                'start_time': current_time,
                'duration': phase_duration,
                'intensity': intensity,
                'type': phase_type
            })
            
            current_time += phase_duration
        
        return pattern
    
    def get_workday_pattern(self):
        """Get realistic workday activity pattern."""
        current_hour = time.localtime().tm_hour
        base_factor = self.get_circadian_factor(current_hour)
        
        # Add workday vs weekend variation
        weekday = time.localtime().tm_wday
        if weekday < 5:  # Monday-Friday
            if 9 <= current_hour <= 17:  # Business hours
                base_factor *= 1.2
            elif current_hour < 6 or current_hour > 22:  # Off hours
                base_factor *= 0.3
        else:  # Weekend
            base_factor *= 0.6
        
        return min(1.0, base_factor)


class NetworkDelaySimulator:
    """Simulates realistic network delays and variations."""
    
    def __init__(self, base_latency=0.02):
        """
        Initialize with base network latency.
        
        Args:
            base_latency: Base network latency in seconds (default: 20ms)
        """
        self.base_latency = base_latency
        self.congestion_factor = 1.0
        self.last_measurements = []
    
    def get_network_delay(self):
        """Get realistic network delay with congestion simulation."""
        # Base latency with random variation (40%)
        delay = self.base_latency * random.uniform(0.6, 1.4)
        
        # Add congestion factor
        delay *= self.congestion_factor
        
        # Simulate occasional packet loss/retransmission (5% chance)
        if random.random() < 0.05:
            delay *= random.uniform(2.0, 5.0)  # Retransmission delay
        
        # Track measurements for adaptive congestion
        self.last_measurements.append(delay)
        if len(self.last_measurements) > 20:
            self.last_measurements.pop(0)
        
        # Adjust congestion factor based on recent performance
        if len(self.last_measurements) >= 10:
            avg_delay = sum(self.last_measurements) / len(self.last_measurements)
            if avg_delay > self.base_latency * 2:
                self.congestion_factor = min(3.0, self.congestion_factor * 1.1)
            else:
                self.congestion_factor = max(0.5, self.congestion_factor * 0.95)
        
        return delay
    
    def simulate_connection_establishment(self):
        """Simulate TCP connection establishment delay."""
        # SYN -> SYN-ACK -> ACK (3-way handshake)
        syn_delay = self.get_network_delay()
        syn_ack_delay = self.get_network_delay()
        ack_delay = self.get_network_delay()
        
        total_delay = syn_delay + syn_ack_delay + ack_delay
        return total_delay
    
    def simulate_data_transfer_delay(self, data_size_bytes):
        """
        Simulate data transfer delay based on size.
        
        Args:
            data_size_bytes: Size of data to transfer
            
        Returns:
            float: Transfer delay in seconds
        """
        # Assume 1 Mbps connection (realistic for constrained scenarios)
        bandwidth_bps = 1_000_000  # 1 Mbps
        
        # Calculate transfer time
        transfer_time = data_size_bytes * 8 / bandwidth_bps
        
        # Add network delay and some variation
        total_delay = transfer_time + self.get_network_delay()
        
        return total_delay