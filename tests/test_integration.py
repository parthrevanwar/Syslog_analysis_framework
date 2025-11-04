#!/usr/bin/env python3
"""
Simple test script to verify the syslog framework works end-to-end.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import sqlite3
from collector.parser import normalize_syslog
from collector.storage import Storage
from collector.analyzer import Analyzer
from datetime import datetime

def test_parser():
    """Test that the parser correctly normalizes syslog messages."""
    print("Testing parser...")
    raw = "Nov  4 10:01:01 lab-server sshd[12345]: Failed password for invalid user alice from 10.0.0.42 port 34567 ssh2"
    src_ip = "10.0.0.42"
    ts = datetime.utcnow().isoformat() + 'Z'
    
    doc = normalize_syslog(raw, src_ip, ts)
    
    assert doc['host'] == 'lab-server', f"Expected host 'lab-server', got '{doc['host']}'"
    assert doc['program'] == 'sshd', f"Expected program 'sshd', got '{doc['program']}'"
    assert doc['parsed']['event_type'] == 'ssh_failed', f"Expected event_type 'ssh_failed', got '{doc['parsed']['event_type']}'"
    assert doc['parsed']['user'] == 'alice', f"Expected user 'alice', got '{doc['parsed']['user']}'"
    assert doc['parsed']['src_ip'] == '10.0.0.42', f"Expected src_ip '10.0.0.42', got '{doc['parsed']['src_ip']}'"
    
    print("✓ Parser test passed")
    return True

def test_storage():
    """Test that storage can save and retrieve logs."""
    print("\nTesting storage...")
    # Remove test database if it exists
    if os.path.exists('test_syslogs.db'):
        os.remove('test_syslogs.db')
    
    # Use SQLite for testing
    storage = Storage(es_host='http://invalid:9999')
    storage.conn = storage.conn or sqlite3.connect('test_syslogs.db', check_same_thread=False)
    storage._init_sqlite()
    
    # Create a test document
    doc = {
        'timestamp': '2024-11-04T10:01:01Z',
        'src_ip': '10.0.0.42',
        'host': 'test-server',
        'program': 'sshd',
        'pid': '12345',
        'parsed': {'event_type': 'ssh_failed'},
        'raw': 'Test log message'
    }
    
    # Store it
    storage.index(doc)
    
    # Retrieve it
    results = storage.search_recent()
    
    assert len(results) > 0, "Expected at least one result"
    assert results[0]['host'] == 'test-server', f"Expected host 'test-server', got '{results[0]['host']}'"
    
    # Clean up
    if os.path.exists('test_syslogs.db'):
        os.remove('test_syslogs.db')
    
    print("✓ Storage test passed")
    return True

def test_analyzer():
    """Test that the analyzer detects brute force attempts."""
    print("\nTesting analyzer...")
    
    class DummyStorage:
        pass
    
    storage = DummyStorage()
    analyzer = Analyzer(storage)
    
    # Simulate 5 failed attempts
    for i in range(5):
        doc = {
            'parsed': {'event_type': 'ssh_failed', 'src_ip': '10.0.0.42'},
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        result = analyzer.process(doc)
    
    # Should trigger on the 5th attempt
    assert result is not None, "Expected alert after 5 failed attempts"
    assert result['type'] == 'ssh_bruteforce_threshold', f"Expected 'ssh_bruteforce_threshold', got '{result['type']}'"
    
    # Now simulate a success
    doc2 = {
        'parsed': {'event_type': 'ssh_success', 'src_ip': '10.0.0.42'},
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    result2 = analyzer.process(doc2)
    
    assert result2 is not None, "Expected alert after success following failures"
    assert result2['type'] == 'intrusion_suspected', f"Expected 'intrusion_suspected', got '{result2['type']}'"
    
    print("✓ Analyzer test passed")
    return True

if __name__ == '__main__':
    print("=" * 60)
    print("Running Syslog Analysis Framework Tests")
    print("=" * 60)
    
    try:
        test_parser()
        test_storage()
        test_analyzer()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
