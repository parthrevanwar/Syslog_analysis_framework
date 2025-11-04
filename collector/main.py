#!/usr/bin/env python3
"""
Simple UDP/TCP syslog server that forwards raw messages to parser -> storage -> analyzer.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import argparse
import asyncio
import logging
import socket
import json
from datetime import datetime
from collector.parser import normalize_syslog
from collector.storage import Storage
from collector.analyzer import Analyzer
from collector.alerting import Alerting

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("collector")

# Short in-memory dedupe cache
RECENT_MSGS = set()

async def handle_udp(reader, addr, storage, analyzer, alerting):
    data, (ip, port) = reader
    text = data.decode(errors='ignore').strip()
    await process_message(text, ip, storage, analyzer, alerting)

async def process_message(raw, src_ip, storage, analyzer, alerting):
    # dedupe window: small set; production should use LRU with TTL
    key = (raw, src_ip)
    if key in RECENT_MSGS:
        return
    RECENT_MSGS.add(key)
    # Limit cache size - remove oldest when exceeding limit
    if len(RECENT_MSGS) > 10000:
        # Create new set with recent items to maintain reasonable size
        oldest = list(RECENT_MSGS)[:5000]
        for item in oldest:
            RECENT_MSGS.discard(item)

    ts = datetime.utcnow().isoformat() + 'Z'
    normalized = normalize_syslog(raw, src_ip, ts)
    # store
    storage.index(normalized)
    # analyze
    alert = analyzer.process(normalized)
    if alert:
        alerting.send(alert)

class UDPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, storage, analyzer, alerting):
        self.storage = storage
        self.analyzer = analyzer
        self.alerting = alerting

    def datagram_received(self, data, addr):
        text = data.decode(errors='ignore').strip()
        src_ip = addr[0]
        asyncio.create_task(process_message(text, src_ip, self.storage, self.analyzer, self.alerting))

async def tcp_client_handler(reader, writer, storage, analyzer, alerting):
    peer = writer.get_extra_info('peername')
    src_ip = peer[0] if peer else 'unknown'
    while True:
        data = await reader.readline()
        if not data:
            break
        text = data.decode(errors='ignore').strip()
        await process_message(text, src_ip, storage, analyzer, alerting)
    writer.close()
    await writer.wait_closed()

async def start_servers(udp_port, tcp_port, es_host):
    storage = Storage(es_host=es_host)
    analyzer = Analyzer(storage)
    alerting = Alerting()

    loop = asyncio.get_running_loop()
    udp_transport, udp_proto = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(storage, analyzer, alerting),
        local_addr=('0.0.0.0', udp_port))

    server = await asyncio.start_server(lambda r, w: tcp_client_handler(r, w, storage, analyzer, alerting), '0.0.0.0', tcp_port)

    logger.info(f"UDP server listening on 0.0.0.0:{udp_port}, TCP on 0.0.0.0:{tcp_port}")

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--udp-port', type=int, default=5514)
    parser.add_argument('--tcp-port', type=int, default=5514)
    parser.add_argument('--es-host', type=str, default='http://localhost:9200')
    args = parser.parse_args()

    try:
        asyncio.run(start_servers(args.udp_port, args.tcp_port, args.es_host))
    except KeyboardInterrupt:
        logger.info('Shutting down')
