"""
Normalize various syslog formats into JSON documents with a consistent schema.
This includes parsing timestamps, host, program, pid, message, and extracting fields from common message types.
"""
import re
from dateutil import parser as dateparser

# Example schema keys: timestamp, src_ip, host, program, pid, severity, message, parsed

RE_SYSLOG = re.compile(r'^(?:<\d+>)?(?:(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(?P<host>[^\s]+)\s+(?P<rest>.+)$')

SSH_FAILED = re.compile(r'Failed password for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>[\d.]+)')
SSH_SUCCESS = re.compile(r'Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>[\d.]+)')

CISCO_LOGIN = re.compile(r'%SEC-.*line.*: Login Authentication for user (?P<user>[^,]+), src (?P<ip>[\d.]+)')

def normalize_syslog(raw, src_ip, received_ts):
    # Try to split into timestamp, host, rest
    m = RE_SYSLOG.match(raw)
    doc = {
        'raw': raw,
        'src_ip': src_ip,
        'received_ts': received_ts,
        'timestamp': None,
        'host': None,
        'program': None,
        'pid': None,
        'severity': None,
        'message': None,
        'parsed': {}
    }
    if m:
        ts = m.group('timestamp')
        host = m.group('host')
        rest = m.group('rest')
        doc['host'] = host
        doc['message'] = rest
        if ts:
            # parse syslog timestamp (no year) => assume current year
            try:
                dt = dateparser.parse(ts)
                doc['timestamp'] = dt.isoformat()
            except Exception:
                doc['timestamp'] = received_ts
        else:
            doc['timestamp'] = received_ts
    else:
        doc['message'] = raw
        doc['timestamp'] = received_ts

    # Extract program/pid if present like: program[123]: message
    prog = re.match(r'(?P<prog>[\w/\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)', doc['message'])
    if prog:
        doc['program'] = prog.group('prog')
        doc['pid'] = prog.group('pid')
        doc['message'] = prog.group('msg')

    # Pattern matches
    m1 = SSH_FAILED.search(doc['message'])
    if m1:
        doc['parsed']['event_type'] = 'ssh_failed'
        doc['parsed']['user'] = m1.group('user')
        doc['parsed']['src_ip'] = m1.group('ip')
        return doc
    m2 = SSH_SUCCESS.search(doc['message'])
    if m2:
        doc['parsed']['event_type'] = 'ssh_success'
        doc['parsed']['user'] = m2.group('user')
        doc['parsed']['src_ip'] = m2.group('ip')
        return doc
    m3 = CISCO_LOGIN.search(doc['message'])
    if m3:
        doc['parsed']['event_type'] = 'cisco_login'
        doc['parsed']['user'] = m3.group('user')
        doc['parsed']['src_ip'] = m3.group('ip')
        return doc

    # Fallback: no structured parse
    doc['parsed']['event_type'] = 'unclassified'
    return doc
