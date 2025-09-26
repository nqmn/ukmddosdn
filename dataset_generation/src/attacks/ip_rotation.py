"""
IP Address Management Module for Advanced DDoS Attacks

This module provides IP rotation functionality to distribute attacks
across multiple source addresses for evasion and load distribution.
"""

import random
import threading
import ipaddress


class IPRotator:
    """Manages IP address rotation for attack distribution."""
    
    def __init__(self, subnets=None):
        """
        Initialize IP rotator with specified subnets.
        
        Args:
            subnets: List of subnet strings (e.g., ["192.168.0.0/16"])
        """
        if subnets is None:
            subnets = ["192.168.0.0/16"]
        self.subnets = [ipaddress.IPv4Network(s) for s in subnets]
        self.used_ips = set()
        self.lock = threading.Lock()
    
    def get_random_ip(self):
        """
        Get a random IP address from configured subnets.
        
        Returns:
            str: Random IP address that hasn't been used recently
        """
        with self.lock:
            # Get a random IP from one of the subnets that hasn't been used recently
            while True:
                chosen_subnet = random.choice(self.subnets)
                random_ip = str(random.choice(list(chosen_subnet.hosts())))
                if random_ip not in self.used_ips:
                    self.used_ips.add(random_ip)
                    # Keep track of last 1000 IPs to avoid reuse
                    if len(self.used_ips) > 1000:
                        self.used_ips.pop()
                    return random_ip