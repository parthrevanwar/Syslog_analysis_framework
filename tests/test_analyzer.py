from collector.analyzer import Analyzer
from collector.storage import Storage
from datetime import datetime, timedelta

class DummyStorage:
    pass

def test_bruteforce_then_success():
    storage = DummyStorage()
    a = Analyzer(storage)
    base = datetime.utcnow()
    # simulate 5 failed attempts from 1.2.3.4
    for i in range(5):
        doc = {'parsed': {'event_type': 'ssh_failed', 'src_ip': '1.2.3.4'}, 'timestamp': (base - timedelta(seconds=10)).isoformat()}
        res = a.process(doc)
    # now a success within window
    doc2 = {'parsed': {'event_type': 'ssh_success', 'src_ip': '1.2.3.4'}, 'timestamp': base.isoformat()}
    res2 = a.process(doc2)
    assert res2 is not None
    assert res2['type'] == 'intrusion_suspected'
