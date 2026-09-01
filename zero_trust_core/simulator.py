import threading
import time

from .auth import AuthManager, DeviceInfo
from .protocol import ZeroTrustClient
from .relay import RelayServer


def build_demo_registry():
    return {
        "alice": DeviceInfo("alice", "alice-secret", {"bob"}),
        "bob": DeviceInfo("bob", "bob-secret", {"alice"}),
    }


def run_local_demo(host: str = "127.0.0.1", port: int = 9000):
    auth_manager = AuthManager(build_demo_registry())
    relay = RelayServer(host=host, port=port, auth_manager=auth_manager)
    relay.start()

    alice = ZeroTrustClient("alice", "alice-secret", host, port)
    bob = ZeroTrustClient("bob", "bob-secret", host, port)

    try:
        alice.connect()
        bob.connect()
        alice.login()
        bob.login()
        alice.connect_to_peer("bob")
        bob.connect_to_peer("alice")

        alice.send_message("bob", "hello-from-alice")
        message = bob.receive_message(timeout=5)
    finally:
        alice.close()
        bob.close()
        relay.shutdown()
    return {
        "alice": alice,
        "bob": bob,
        "message": message,
    }
