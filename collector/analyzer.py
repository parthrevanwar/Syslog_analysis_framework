"""
Simple rule-based correlation engine.
Rule example implemented:
- If >= N failed ssh attempts from same IP within T minutes, followed by a successful ssh login from same IP within T2 minutes -> raise an alert.
"""
import logging
from collections import deque, defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger('analyzer')

class Analyzer:
    def __init__(self, storage):
        self.storage = storage
        # keep an in-memory window of recent failed attempts: ip -> deque of timestamps
        self.failed_ssh = defaultdict(deque)
        # settings
        self.fail_window = timedelta(minutes=10)
        self.fail_threshold = 5
        self.success_follow_window = timedelta(minutes=5)

    def _parse_time(self, ts):
        try:
            return datetime.fromisoformat(ts.replace('Z', ''))
        except Exception:
            return datetime.utcnow()

    def process(self, doc):
        et = doc.get('parsed', {}).get('event_type')
        if et == 'ssh_failed':
            ip = doc.get('parsed', {}).get('src_ip') or doc.get('src_ip')
            now = self._parse_time(doc.get('timestamp'))
            dq = self.failed_ssh[ip]
            dq.append(now)
            # drop old
            while dq and (now - dq[0]) > self.fail_window:
                dq.popleft()
            if len(dq) >= self.fail_threshold:
                logger.info('SSH brute force suspect from %s: %d fails in %s', ip, len(dq), self.fail_window)
                return {
                    'type': 'ssh_bruteforce_threshold',
                    'ip': ip,
                    'count': len(dq),
                    'message': f'Suspected brute force: {len(dq)} failed SSH logins from {ip} in {self.fail_window}'
                }
            return None
        elif et == 'ssh_success':
            ip = doc.get('parsed', {}).get('src_ip') or doc.get('src_ip')
            now = self._parse_time(doc.get('timestamp'))
            dq = self.failed_ssh.get(ip, deque())
            # check if there were failed attempts in window before success
            if dq and (now - dq[-1]) <= self.success_follow_window:
                # correlation: failed attempts followed by success
                logger.warning('Intrusion pattern: failed attempts then success from %s', ip)
                return {
                    'type': 'intrusion_suspected',
                    'ip': ip,
                    'message': f'Failed SSH attempts followed by success from {ip}'
                }
            return None
        else:
            return None
