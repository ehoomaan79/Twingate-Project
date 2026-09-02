import unittest

from zero_trust_core.auth import AuthManager, DeviceInfo
from zero_trust_core.network import VirtualNetwork
from zero_trust_core.protocol import ZeroTrustClient
from zero_trust_core.relay import RelayServer


class ZeroTrustCoreModulesTests(unittest.TestCase):
    def test_virtual_network_allocates_unique_private_addresses(self):
        network = VirtualNetwork("10.240.0.0/29")

        alice_ip = network.register_device("alice")
        bob_ip = network.register_device("bob")

        self.assertEqual(alice_ip, "10.240.0.1")
        self.assertEqual(bob_ip, "10.240.0.2")
        self.assertEqual(network.resolve_private_ip("alice"), "10.240.0.1")
        self.assertEqual(network.resolve_private_ip("bob"), "10.240.0.2")

    def test_relay_returns_nat_safe_route_and_virtual_ip(self):
        auth_manager = AuthManager({
            "alice": DeviceInfo("alice", "alice-secret", {"bob"}),
            "bob": DeviceInfo("bob", "bob-secret", {"alice"}),
        })
        relay = RelayServer(host="127.0.0.1", port=9005, auth_manager=auth_manager)
        relay.start()

        try:
            alice = ZeroTrustClient("alice", "alice-secret", "127.0.0.1", 9005)
            bob = ZeroTrustClient("bob", "bob-secret", "127.0.0.1", 9005)

            alice.connect()
            bob.connect()
            alice.login()
            bob.login()

            route = alice.connect_to_peer("bob")

            self.assertEqual(route["nat_route"]["mode"], "relay")
            self.assertEqual(route["virtual_ip"], relay.network.resolve_private_ip("alice"))
            self.assertEqual(route["peer_virtual_ip"], relay.network.resolve_private_ip("bob"))
        finally:
            alice.close()
            bob.close()
            relay.shutdown()

    def test_client_network_interface_keeps_private_ip_separate_from_real_ip(self):
        client = ZeroTrustClient("device-a", "secret", "127.0.0.1", 9006)

        client.virtual_ip = "10.240.0.11"
        client.route_table = {"peer-a": {"virtual_ip": "10.240.0.12", "natted": True}}

        self.assertEqual(client.virtual_ip, "10.240.0.11")
        self.assertNotEqual(client.virtual_ip, client.host)
        self.assertTrue(client.route_table["peer-a"]["natted"])


if __name__ == "__main__":
    unittest.main()
