import subprocess
from pathlib import Path
from datetime import datetime
import json

LOG_FILE = Path("/var/log/netmancer.log")

def log_message(message):
    """Write logs to /var/log/netmancer.log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    try:
        with LOG_FILE.open("a") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def configure_parser(subparsers):
    """Configures the command-line argument parser for showinfo."""
    parser = subparsers.add_parser('dhcpinfo', help='Show DHCP server information about the given device interface')
    parser.add_argument('--interface', '-i', required=True, help='Ethernet interface name (e.g., eth0)')
    parser.set_defaults(func=handle_dhcpinfo)

def handle_dhcpinfo(args):
    """Handles the dhcpinfo command."""
    interface = args.interface
    interface_details = get_interface_details(interface)

    if interface_details:
        print(json.dumps(interface_details, indent=4))
    else:
        print(f"Interface {interface} is not connected.")

def get_interface_details(interface):
    """Get details of the DHCP server for the given interface using nmcli DHCP4.OPTION"""
    try:
        result = subprocess.run(
            ["nmcli", "--terse", "--fields", "DHCP4.OPTION", "device", "show", interface],
            capture_output=True, text=True, check=True
        )
        output = result.stdout.strip().split("\n")

        if not output or all(line.strip() == "" for line in output):
            log_message(f"WARNING: No DHCP information found for interface {interface}.")
            return {}

        dhcp_details = {
            "dhcp_server_identifier": "NA",
            "domain_name_servers": "NA",
            "domain_name": "NA",
            "routers": "NA",
            "ntp_servers": "NA",
            "host_name": "NA",
            "ip_address": "NA",
            "subnet_mask": "NA"
        }

        for line in output:
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

            if key.startswith("DHCP4.OPTION") and ":" in key:
                _, field_name = key.split(":", 1)
                field_name = field_name.strip()

                if field_name == "dhcp_server_identifier":
                    dhcp_details["dhcp_server_identifier"] = value
                elif field_name == "domain_name_servers":
                    dhcp_details["domain_name_servers"] = value if value != "1" else "NA"
                elif field_name == "domain_name":
                    dhcp_details["domain_name"] = value if value != "1" else "NA"
                elif field_name == "routers":
                    dhcp_details["routers"] = value
                elif field_name == "ntp_servers":
                    dhcp_details["ntp_servers"] = value
                elif field_name == "ip_address":
                    dhcp_details["ip_address"] = value
                elif field_name == "subnet_mask":
                    dhcp_details["subnet_mask"] = value
        # Get hostname
        dhcp_details["host_name"] = get_system_hostname()
        log_message(f"INFO: Retrieved DHCP server details for {interface}: {dhcp_details}")
        return dhcp_details

    except subprocess.CalledProcessError as e:
        log_message(f"ERROR: Failed to get DHCP server details for {interface}: {e}")
        return {}

def get_system_hostname():
    try:
        result = subprocess.run(["hostnamectl", "--static"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "NA"
