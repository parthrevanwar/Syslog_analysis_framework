#!/usr/bin/env python3
"""
Script to send sample logs to the collector for testing.
Usage: python send_logs.py [--host localhost] [--port 5514]
"""
import socket
import sys
import argparse
import time

def send_logs_tcp(host, port, log_file):
    """Send logs to collector via TCP."""
    print(f"Sending logs to {host}:{port} via TCP...")
    
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        for log in logs:
            if log.strip():
                # Send log as-is, ensuring it ends with newline
                msg = log if log.endswith('\n') else log + '\n'
                sock.sendall(msg.encode())
                print(f"  Sent: {log[:60]}...")
                time.sleep(0.1)
        print(f"\n✓ Successfully sent {len(logs)} logs")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
    finally:
        sock.close()

def send_logs_udp(host, port, log_file):
    """Send logs to collector via UDP."""
    print(f"Sending logs to {host}:{port} via UDP...")
    
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for log in logs:
            if log.strip():
                sock.sendto(log.encode(), (host, port))
                print(f"  Sent: {log[:60]}...")
                time.sleep(0.1)
        print(f"\n✓ Successfully sent {len(logs)} logs")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
    finally:
        sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send sample logs to syslog collector')
    parser.add_argument('--host', default='localhost', help='Collector host')
    parser.add_argument('--port', type=int, default=5514, help='Collector port')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='Protocol to use')
    parser.add_argument('--file', default='sample_data/sample_syslogs.txt', help='Log file to send')
    args = parser.parse_args()
    
    if args.protocol == 'tcp':
        send_logs_tcp(args.host, args.port, args.file)
    else:
        send_logs_udp(args.host, args.port, args.file)
