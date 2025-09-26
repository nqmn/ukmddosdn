"""
DEPRECATED: This file has been refactored into multiple modules for better maintainability.

Please use the refactored modules instead:
- ip_rotation.py: IPRotator class
- packet_crafting.py: PacketCrafter class  
- advanced_techniques.py: AdvancedTechniques class
- session_management.py: SessionMaintainer class
- adaptive_control.py: AdaptiveController class
- ddos_coordinator.py: AdvancedDDoSCoordinator class
- gen_advanced_adversarial_ddos_attacks_refactored.py: run_attack function

For backward compatibility, this file re-exports the refactored components.
"""

import warnings
warnings.warn(
    "gen_advanced_adversarial_ddos_attacks.py is deprecated. "
    "Use the refactored modules or import from gen_advanced_adversarial_ddos_attacks_refactored.py",
    DeprecationWarning,
    stacklevel=2
)

# Re-export all components for backward compatibility
try:
    # Try relative imports first (when used as package)
    from .ip_rotation import IPRotator
    from .packet_crafting import PacketCrafter
    from .advanced_techniques import AdvancedTechniques
    from .session_management import SessionMaintainer
    from .adaptive_control import AdaptiveController
    from .ddos_coordinator import AdvancedDDoSCoordinator
    from .gen_advanced_adversarial_ddos_attacks_refactored import run_attack
except ImportError:
    # Fall back to absolute imports (when used directly)
    from ip_rotation import IPRotator
    from packet_crafting import PacketCrafter
    from advanced_techniques import AdvancedTechniques
    from session_management import SessionMaintainer
    from adaptive_control import AdaptiveController
    from ddos_coordinator import AdvancedDDoSCoordinator
    from gen_advanced_adversarial_ddos_attacks_refactored import run_attack

import logging

# Get the centralized attack logger  
attack_logger = logging.getLogger('attack_logger')

# All functionality has been moved to separate modules
# The original classes and functions are available through the imports above