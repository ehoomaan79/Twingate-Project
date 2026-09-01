import argparse

from zero_trust_core.auth import AuthManager, DeviceInfo
from zero_trust_core.relay import RelayServer


def build_default_registry():
    return {
        "alice": DeviceInfo("alice", "alice-secret", {"bob"}),
        "bob": DeviceInfo("bob", "bob-secret", {"alice"}),
        "charlie": DeviceInfo("charlie", "charlie-secret", {"dana"}),
        "dana": DeviceInfo("dana", "dana-secret", {"charlie"}),
    }


def main():
    parser = argparse.ArgumentParser(description="Start the zero-trust relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    auth_manager = AuthManager(build_default_registry())
    relay = RelayServer(host=args.host, port=args.port, auth_manager=auth_manager)
    print(f"Zero-trust relay listening on {args.host}:{args.port}")
    relay.serve_forever()


if __name__ == "__main__":
    main()
