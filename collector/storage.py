"""
Storage abstraction: Elasticsearch (preferred) with SQLite fallback for demo.
"""
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger('storage')

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except Exception:
    ES_AVAILABLE = False

import sqlite3

class Storage:
    def __init__(self, es_host='http://localhost:9200'):
        self.es_host = es_host
        self.es = None
        self.use_es = False
        if ES_AVAILABLE:
            try:
                # Try newer Elasticsearch client syntax first with reduced timeout
                try:
                    self.es = Elasticsearch([es_host], request_timeout=5, max_retries=0, retry_on_timeout=False)
                except TypeError:
                    # Fall back to older syntax
                    self.es = Elasticsearch([es_host])
                # simple health check
                if self.es.ping():
                    self.use_es = True
                    logger.info('Connected to Elasticsearch')
            except Exception as e:
                logger.warning('Elasticsearch not available: %s', e)
        if not self.use_es:
            logger.info('Using SQLite for storage')
            self.conn = sqlite3.connect('syslogs.db', check_same_thread=False)
            self._init_sqlite()

    def _init_sqlite(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            src_ip TEXT,
            host TEXT,
            program TEXT,
            pid TEXT,
            event_type TEXT,
            raw TEXT
        )''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_event ON logs(event_type)''')
        self.conn.commit()

    def index(self, doc):
        if self.use_es:
            try:
                idx = 'syslogs'
                body = doc.copy()
                self.es.index(index=idx, body=body)
            except Exception as e:
                logger.exception('ES index error: %s', e)
        else:
            c = self.conn.cursor()
            c.execute('INSERT INTO logs (ts, src_ip, host, program, pid, event_type, raw) VALUES (?, ?, ?, ?, ?, ?, ?)', (
                doc.get('timestamp'), doc.get('src_ip'), doc.get('host'), doc.get('program'), doc.get('pid'), doc.get('parsed', {}).get('event_type'), doc.get('raw')
            ))
            self.conn.commit()

    def search_recent(self, minutes=60, event_type=None, src_ip=None):
        # Basic sqlite search for demo
        if self.use_es:
            # ES query implementation (left simple)
            q = {"query": {"match_all": {}}}
            res = self.es.search(index='syslogs', body=q, size=100)
            return [r['_source'] for r in res['hits']['hits']]
        else:
            c = self.conn.cursor()
            q = 'SELECT ts, src_ip, host, program, pid, event_type, raw FROM logs'
            conditions = []
            params = []
            if event_type:
                conditions.append('event_type = ?')
                params.append(event_type)
            if src_ip:
                conditions.append('src_ip = ?')
                params.append(src_ip)
            if conditions:
                q += ' WHERE ' + ' AND '.join(conditions)
            q += ' ORDER BY id DESC LIMIT 200'
            c.execute(q, params)
            rows = c.fetchall()
            results = []
            for r in rows:
                results.append(dict(ts=r[0], src_ip=r[1], host=r[2], program=r[3], pid=r[4], event_type=r[5], raw=r[6]))
            return results
