import tempfile
import unittest
from pathlib import Path

from controller.database import ControllerDatabase


class ControllerDatabaseTests(unittest.TestCase):
    def test_connector_enrollment_token_is_single_use(self):
        db = ControllerDatabase()
        token = db.create_connector_token("connector-1")

        self.assertTrue(db.consume_connector_token(token, "connector-1"))
        self.assertFalse(db.consume_connector_token(token, "connector-1"))
        self.assertFalse(db.consume_connector_token(token, "connector-2"))

    def test_controller_database_persists_state_across_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "controller.db"
            first = ControllerDatabase(database_path)
            first.register_user("alice", groups={"ops"})
            first.register_relay("relay-1", "relay.example", 9000)
            first.close()

            second = ControllerDatabase(database_path)
            try:
                self.assertIn("alice", second.users)
                self.assertIn("ops", second.groups)
                self.assertIn("relay-1", second.relays)
            finally:
                second.close()

    def test_controller_database_tracks_users_groups_and_resources(self):
        db = ControllerDatabase()

        db.register_user("alice", groups={"ops"}, roles={"admin"})
        db.create_group("ops", description="Operations")
        db.register_resource("db-prod", allowed_groups={"ops"}, allowed_ports={5432, 443})
        db.register_relay("relay-1", "10.0.0.10", 9000)
        db.register_connector("conn-1", "10.0.0.20", 9100, "10.240.1.10")
        db.register_client("client-a", "10.0.0.30", 9200, "10.240.0.5")

        self.assertIn("alice", db.users)
        self.assertIn("ops", db.groups)
        self.assertEqual(db.resources["db-prod"]["allowed_ports"], {5432, 443})
        self.assertIn("relay-1", db.relays)
        self.assertIn("conn-1", db.connectors)
        self.assertIn("client-a", db.clients)

    def test_controller_database_enforces_resource_access_policy(self):
        db = ControllerDatabase()
        db.register_user("bob", groups={"engineering"}, roles={"user"})
        db.create_group("engineering", description="Engineering")
        db.register_resource("api-prod", allowed_groups={"engineering"}, allowed_ports={443}, require_mfa=True)

        self.assertTrue(db.can_access("bob", "api-prod", 443, mfa_verified=True, device_trusted=True, device_compliant=True))
        self.assertFalse(db.can_access("bob", "api-prod", 80, mfa_verified=True, device_trusted=True, device_compliant=True))

    def test_controller_lists_only_visible_resources_for_authorized_user(self):
        db = ControllerDatabase()
        db.register_user("alice", groups={"ops"})
        db.register_resource("internal-api", address="api.internal", allowed_groups={"ops"}, allowed_ports={443}, dns_servers=["10.0.0.53"])
        db.register_resource("hidden-api", address="hidden.internal", allowed_groups={"ops"}, visible=False)

        resources = db.list_accessible_resources("alice", device_trusted=True, device_compliant=True)

        self.assertEqual([item["resource_id"] for item in resources], ["internal-api"])
        self.assertEqual(resources[0]["dns_servers"], ["10.0.0.53"])

    def test_controller_resolves_authorized_route_to_relay_and_connector(self):
        db = ControllerDatabase()
        db.register_user("alice", groups={"ops"}, roles={"admin"})
        db.create_group("ops", description="Operations")
        db.register_relay("relay-1", "10.0.0.10", 9000)
        db.register_connector("conn-1", "10.0.0.20", 9100, "10.240.1.10")
        db.register_resource("db-prod", allowed_groups={"ops"}, allowed_ports={5432}, connector_id="conn-1", relay_id="relay-1")

        route = db.resolve_access("alice", "db-prod", 5432, mfa_verified=True, device_trusted=True, device_compliant=True)

        self.assertTrue(route["authorized"])
        self.assertEqual(route["relay"]["relay_id"], "relay-1")
        self.assertEqual(route["connector"]["connector_id"], "conn-1")


if __name__ == "__main__":
    unittest.main()
