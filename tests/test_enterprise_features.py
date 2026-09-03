import threading
import unittest

from modules.client.service import ClientService

from zero_trust_core.encryption import SessionCipher
from zero_trust_core.dns import find_resource
from zero_trust_core.tunnel import EncryptedEnvelope
from zero_trust_core.kernel_routing import LinuxRouteManager
from zero_trust_core.policy import AccessRequest, PolicyEngine


class EnterpriseFeatureTests(unittest.TestCase):
    def test_relay_payload_is_end_to_end_encrypted(self):
        envelope = EncryptedEnvelope.seal(b"private-resource-request", "client-connector-session", b"channel-1")

        self.assertNotIn(b"private-resource-request", envelope.ciphertext.encode("ascii"))
        self.assertEqual(envelope.open("client-connector-session", b"channel-1"), b"private-resource-request")
        with self.assertRaises(Exception):
            envelope.open("wrong-secret", b"channel-1")

    def test_client_tls_context_requires_tls_one_three(self):
        import ssl
        from zero_trust_core.tunnel import client_tls_context

        self.assertEqual(client_tls_context().minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_connector_bridge_forwards_bytes_in_both_directions(self):
        import socket
        import time
        from modules.connector.service import ConnectorService

        left, right = socket.socketpair()
        threading.Thread(target=ConnectorService._bridge, args=(left, right), daemon=True).start()
        left.settimeout(2)
        right.settimeout(2)
        left.sendall(b"to-private-service")
        self.assertEqual(right.recv(1024), b"to-private-service")
        right.sendall(b"to-client")
        self.assertEqual(left.recv(1024), b"to-client")
        left.close()
        right.close()
        time.sleep(0.01)

    def test_resource_alias_and_private_fqdn_match_without_public_dns(self):
        resources = [{"resource_id": "db", "address": "db.internal", "aliases": {"database.home"}}]

        self.assertEqual(find_resource(resources, "database.home")["resource_id"], "db")
        self.assertEqual(find_resource(resources, "db.internal")["resource_id"], "db")

    def test_client_only_intercepts_acl_matches_and_leaves_other_traffic_local(self):
        resources = [{
            "resource_id": "db",
            "address": "db.internal",
            "aliases": {"database.home"},
            "allowed_ports": {5432},
            "allowed_protocols": {"tcp"},
        }]

        protected = ClientService.interception_decision(resources, "database.home", 5432, "tcp")
        ordinary = ClientService.interception_decision(resources, "public.example", 443, "tcp")
        blocked = ClientService.interception_decision(resources, "db.internal", 443, "tcp")

        self.assertTrue(protected["intercept"])
        self.assertEqual(protected["route"], "tunnel")
        self.assertEqual(ordinary, {"intercept": False, "route": "local", "reason": "not_in_acl"})
        self.assertEqual(blocked["route"], "blocked")

    def test_session_cipher_encrypts_and_decrypts_message(self):
        cipher = SessionCipher.from_shared_secret("demo-secret", salt=b"enterprise-demo")
        payload = b"secure payload for tunnel"

        encrypted = cipher.encrypt(payload, associated_data=b"device-a->device-b")
        decrypted = cipher.decrypt(encrypted, associated_data=b"device-a->device-b")

        self.assertEqual(decrypted, payload)

    def test_dynamic_policy_evaluates_user_and_device_context(self):
        engine = PolicyEngine()
        engine.add_resource(
            "database-prod",
            allowed_groups={"ops", "db-admins"},
            allowed_users={"admin-user"},
            allowed_ports={443, 5432},
            require_mfa=True,
        )

        request = AccessRequest(
            user_id="admin-user",
            groups={"ops"},
            device_id="laptop-01",
            resource_id="database-prod",
            port=5432,
            mfa_verified=True,
            device_trusted=True,
            device_compliant=True,
        )

        self.assertTrue(engine.evaluate_access(request))

    def test_linux_route_manager_builds_ip_route_command(self):
        manager = LinuxRouteManager(interface_name="ztna0")
        command = manager.build_route_command("10.240.0.0/24", "10.240.0.1")

        self.assertIn("ip route add 10.240.0.0/24 via 10.240.0.1 dev ztna0", command)


if __name__ == "__main__":
    unittest.main()
