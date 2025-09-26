"""
Refactored Advanced Adversarial DDoS Attacks Module

This module provides the main entry point for executing advanced adversarial DDoS attacks
with improved modularity and maintainability.
"""

import os
import re
import time
import signal
import logging
import subprocess
import uuid
from pathlib import Path

try:
    from .ddos_coordinator import AdvancedDDoSCoordinator
except ImportError:
    from ddos_coordinator import AdvancedDDoSCoordinator

# Import standardized logging
try:
    from ..utils.logger import get_attack_logger, with_run_id
except ImportError:
    try:
        from utils.logger import get_attack_logger, with_run_id
    except ImportError:
        # Fallback to basic logging
        def get_attack_logger(log_dir=None):
            return logging.getLogger('attack_logger')
        def with_run_id(run_id, logger):
            class MockContext:
                def __enter__(self): return logger
                def __exit__(self, *args): pass
            return MockContext()


def run_attack(attacker_host, victim_ip, duration, attack_variant="slow_read", output_dir=None):
    """
    Execute advanced adversarial DDoS attacks against a target.
    
    Args:
        attacker_host: Mininet host object for the attacker
        victim_ip: Target IP address
        duration: Attack duration in seconds
        attack_variant: Type of attack ("slow_read", "ad_syn", "ad_udp")
        output_dir: Directory for output logs
    
    Returns:
        subprocess.Popen or None: Process object for slow_read attacks, None for others
    """
    run_id = str(uuid.uuid4())  # Generate a unique ID for this attack run
    
    # Get standardized attack logger
    attack_logger = get_attack_logger(Path(output_dir) if output_dir else None)
    
    # Use run context for consistent run ID logging
    with with_run_id(run_id, attack_logger) as logger:
        logger.info(f"[{attack_variant}] Starting advanced adversarial attack against {victim_ip} for {duration} seconds.")
    coordinator = AdvancedDDoSCoordinator(victim_ip)

    attack_results = {}  # Dictionary to store results for summary

    if attack_variant == "slow_read":
        # Advanced slow HTTP attack with IP rotation and burst patterns
        results = coordinator.advanced.advanced_slow_http_attack(victim_ip, duration=duration, run_id=run_id, attack_variant=attack_variant)
        attack_results[attack_variant] = results
        return None  # No process to return for advanced implementation
        
    elif attack_variant == "ad_syn":
        # Advanced TCP SYN attack
        results = coordinator.advanced.tcp_state_exhaustion(victim_ip, duration=duration, run_id=run_id, attack_variant=attack_variant)
        attack_results[attack_variant] = results
        
    elif attack_variant == "ad_udp":
        # Advanced UDP application layer attack
        results = coordinator.advanced.distributed_application_layer_attack(victim_ip, duration=duration, run_id=run_id, attack_variant=attack_variant)
        attack_results[attack_variant] = results
        
    else:
        attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Unknown attack variant: {attack_variant}. No specific attack executed.")
        attack_results[attack_variant] = {"status": "unknown_variant", "message": "No specific attack executed for this variant."}
        return None
    
    # Final summary for ad_syn, ad_udp, and slow_read
    if attack_variant in ["ad_syn", "ad_udp", "slow_read"] and attack_results.get(attack_variant):
        summary = attack_results[attack_variant]
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] --- Attack Summary ---")
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Total {summary.get('type', 'packets/requests')} sent: {summary.get('total_sent', 0)}")
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] Average rate: {summary.get('average_rate', 0):.2f} {summary.get('type', 'packets/requests')}/sec")
        if summary.get('warning_message'):
            attack_logger.warning(f"[{attack_variant}] [Run ID: {run_id}] Warning: {summary['warning_message']}")
        attack_logger.info(f"[{attack_variant}] [Run ID: {run_id}] --------------------")
    
    return None  # For ad_syn, ad_udp, and slow_read, no direct process to return