class LinuxRouteManager:
    """Build commands for Linux route installation used by a virtual tunnel interface."""

    def __init__(self, interface_name: str, table_name: str | None = None):
        self.interface_name = interface_name
        self.table_name = table_name or "ztna-main"

    def build_route_command(self, destination_cidr: str, next_hop_ip: str) -> str:
        return f"ip route add {destination_cidr} via {next_hop_ip} dev {self.interface_name}"

    def build_delete_command(self, destination_cidr: str) -> str:
        return f"ip route del {destination_cidr} dev {self.interface_name}"
