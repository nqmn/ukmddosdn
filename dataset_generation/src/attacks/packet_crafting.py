"""Utilities for crafting realistic network packets with Scapy."""

from __future__ import annotations

import logging
import random
from typing import Iterable

from scapy.all import IP, TCP, Raw

attack_logger = logging.getLogger('attack_logger')


class PacketCrafter:
    """Create TCP and HTTP packets with varied characteristics."""

    def __init__(self) -> None:
        self.user_agents: list[str] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        ]
        self.http_methods = ["GET", "POST", "HEAD", "OPTIONS"]
        self.http_paths = [
            "/",
            "/index.html",
            "/api/v1/users",
            "/products",
            "/login",
            "/static/css/main.css",
            "/images/banner.jpg",
        ]
        self.common_headers: dict[str, str] = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

    def craft_tcp_packet(self, src: str, dst: str, dport: int = 80) -> IP:
        """Return a TCP packet with randomised metadata."""
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 2**32 - 1)
        flags = random.choice(["S", "SA", "A", "PA", "FA"])
        window = random.randint(8192, 65535)
        ttl = random.randint(48, 128)

        packet = IP(src=src, dst=dst, ttl=ttl) / TCP(
            sport=sport,
            dport=dport,
            seq=seq,
            window=window,
            flags=flags,
        )
        attack_logger.debug(
            "Crafted TCP packet",
            extra={"src": src, "dst": dst, "sport": sport, "dport": dport, "flags": flags, "ttl": ttl},
        )
        return packet

    def _build_http_headers(self, dst: str, user_agent: str) -> dict[str, str]:
        headers = dict(self.common_headers)
        headers["User-Agent"] = user_agent
        headers["Host"] = dst
        if random.random() > 0.7:
            headers["Referer"] = f"https://{random.choice(['google.com', 'bing.com', 'duckduckgo.com'])}/?q=products"
        return headers

    def craft_http_packet(self, src: str, dst: str, dport: int = 80) -> IP:
        """Create a TCP packet carrying an HTTP request."""
        base_packet = self.craft_tcp_packet(src, dst, dport)
        method = random.choice(self.http_methods)
        path = random.choice(self.http_paths)
        user_agent = random.choice(self.user_agents)
        headers = self._build_http_headers(dst, user_agent)

        body = ""
        if method == "POST":
            body = "param1=value1&param2=value2"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))

        http_request = [f"{method} {path} HTTP/1.1"]
        for header, value in headers.items():
            http_request.append(f"{header}: {value}")
        http_request.append("")
        if body:
            http_request.append(body)
        payload = "\r\n".join(http_request) + "\r\n"

        packet = base_packet / Raw(load=payload.encode())
        attack_logger.debug(
            "Crafted HTTP packet",
            extra={"method": method, "path": path, "user_agent": user_agent, "host": dst},
        )
        return packet


__all__ = ['PacketCrafter']
