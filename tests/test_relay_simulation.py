import unittest

from zero_trust_core.auth import AuthManager, DeviceInfo
from zero_trust_core.protocol import ZeroTrustClient
from zero_trust_core.relay import RelayServer


class RelaySimulationTests(unittest.TestCase):
    def test_zero_trust_auth_and_peer_message(self):
        auth_manager = AuthManager({
            "alice": DeviceInfo("alice", "alice-secret", {"bob"}),
            "bob": DeviceInfo("bob", "bob-secret", {"alice"}),
        })
        relay = RelayServer(host="127.0.0.1", port=9001, auth_manager=auth_manager)
        relay.start()

        try:
            alice = ZeroTrustClient("alice", "alice-secret", "127.0.0.1", 9001)
            bob = ZeroTrustClient("bob", "bob-secret", "127.0.0.1", 9001)

            alice.connect()
            bob.connect()
            alice.login()
            bob.login()
            alice.connect_to_peer("bob")
            bob.connect_to_peer("alice")
            alice.send_message("bob", "hello-from-alice")

            received = bob.receive_message(timeout=5)
            self.assertEqual(received["payload"], "hello-from-alice")
            self.assertEqual(received["from"], "alice")
        finally:
            alice.close()
            bob.close()
            relay.shutdown()

    def test_unauthorized_peer_request_is_blocked(self):
        auth_manager = AuthManager({
            "alice": DeviceInfo("alice", "alice-secret", set()),
            "bob": DeviceInfo("bob", "bob-secret", {"alice"}),
        })
        relay = RelayServer(host="127.0.0.1", port=9002, auth_manager=auth_manager)
        relay.start()

        try:
            alice = ZeroTrustClient("alice", "alice-secret", "127.0.0.1", 9002)
            bob = ZeroTrustClient("bob", "bob-secret", "127.0.0.1", 9002)

            alice.connect()
            bob.connect()
            alice.login()
            bob.login()

            with self.assertRaises(RuntimeError):
                alice.connect_to_peer("bob")
        finally:
            alice.close()
            bob.close()
            relay.shutdown()


if __name__ == "__main__":
    unittest.main()
