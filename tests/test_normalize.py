import unittest
import sys
import os
import json

# Add module path to import normalize
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../services/worker/worker')))

# Mock psycopg2 for local testing without drivers
class MockPsycopg2:
    def connect(self, *args, **kwargs): pass
class MockExtras:
    DictCursor = object
    def execute_values(self, *args, **kwargs): pass

sys.modules['psycopg2'] = MockPsycopg2()
sys.modules['psycopg2.extras'] = MockExtras()

import normalize

class TestNormalize(unittest.TestCase):

    def test_classify_wazuh(self):
        row = {"sourcetype": "wazuh-alerts", "source": "firebase"}
        vendor, kind = normalize.classify(row)
        self.assertEqual(vendor, "wazuh")
        self.assertEqual(kind, "alert")

    def test_classify_suricata(self):
        row = {"sourcetype": "suricata", "source": "udp:5514"}
        vendor, kind = normalize.classify(row)
        self.assertEqual(vendor, "suricata")
        self.assertEqual(kind, "alert")
    
    def test_classify_zenarmor(self):
        row = {"sourcetype": "zenarmor", "source": "udp:5514"}
        vendor, kind = normalize.classify(row)
        self.assertEqual(vendor, "zenarmor")
        self.assertEqual(kind, "network")

    def test_classify_juiceshop(self):
        row = {"sourcetype": "juiceshop:app", "source": "http:8088"}
        vendor, kind = normalize.classify(row)
        self.assertEqual(vendor, "juiceshop")
        self.assertEqual(kind, "app")

    def test_extract_wazuh(self):
        # Fixture 1: Wazuh Alert
        raw = {
            "rule": {"id": "5710", "level": 5, "description": "SSHD attempt"},
            "data": {
                "srcip": "192.168.1.100",
                "dstip": "172.16.58.50",
                "srcuser": "attacker"
            }
        }
        row = {}
        fields = normalize.extract_fields("wazuh", row, raw)
        self.assertEqual(fields["signature"], "SSHD attempt")
        self.assertEqual(fields["severity"], 5)
        self.assertEqual(fields["src_ip"], "192.168.1.100")
        self.assertEqual(fields["username"], "attacker")

    def test_extract_suricata(self):
        # Fixture 2: Suricata EVE
        raw = {
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "alert": {
                "signature": "ET TROJAN DNS Query",
                "severity": 1
            }
        }
        row = {}
        fields = normalize.extract_fields("suricata", row, raw)
        self.assertEqual(fields["signature"], "ET TROJAN DNS Query")
        self.assertEqual(fields["severity"], 1)
        self.assertEqual(fields["src_ip"], "10.0.0.5")

    def test_extract_zenarmor(self):
        # Fixture 3: Zenarmor IPDR
        raw = {
            "src_ip": "172.16.58.61",
            "dest_ip": "1.1.1.1",
            "app_proto": "dns",
            "transport_proto": "udp",
            "policy_status": "allowed"
        }
        row = {}
        fields = normalize.extract_fields("zenarmor", row, raw)
        self.assertEqual(fields["signature"], "dns/udp")
        self.assertEqual(fields["severity"], "info")

    def test_extract_juiceshop(self):
        # Fixture 4: JuiceShop
        raw = {
            "method": "GET",
            "path": "/rest/admin/application-configuration",
            "statusCode": 200,
            "user": "admin@juice.sh"
        }
        row = {}
        fields = normalize.extract_fields("juiceshop", row, raw)
        self.assertEqual(fields["signature"], "GET /rest/admin/application-configuration")
        self.assertEqual(fields["http_method"], "GET")
        self.assertEqual(fields["username"], "admin@juice.sh")

    def test_extract_fallback(self):
        # Fixture 5: Generic JSON with just common fields
        raw = {
            "clientip": "1.2.3.4",
            "username": "blob_user"
        }
        row = {"sourcetype": "generic"}
        fields = normalize.extract_fields("generic", row, raw)
        self.assertEqual(fields["src_ip"], "1.2.3.4")
        self.assertEqual(fields["username"], "blob_user")

if __name__ == '__main__':
    unittest.main()
