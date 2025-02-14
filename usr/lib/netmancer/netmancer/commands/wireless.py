import subprocess
import yaml
import configparser
from pathlib import Path
from datetime import datetime
import sqlite3

CONFIG_DIR = Path("/etc/netplan")
SYSCONF_DB = '/data/sysconf.db'
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
    """Configures the command-line argument parser for Wireless settings."""
    parser = subparsers.add_parser('wireless', help='Configure Wireless interface')
    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='Ethernet interface name (e.g., eth0)'
    )
    parser.add_argument(
        '--dhcp', '-d',
        metavar="CONFIG_FILE",
        help='Configure DHCP. Provide the path to the INI configuration file.'
    )

    parser.set_defaults(func=handle_wireless)

def handle_wireless(args):
    """Handles Wireless configuration based on user input."""
    if args.dhcp:
        configure_dhcp(args.interface, args.dhcp)
    else:
        log_message("Error: Invalid network configuration argument.")
        return False

def configure_dhcp(interface, config_ini_path):
    """Configure an Wireless interface with DHCP"""
    dhcp_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-static.yaml"

    # Remove static Netplan YAML if it exists
    if static_netplan_config.exists():
        try:
            static_netplan_config.unlink()
            log_message(f"INFO: Removed {static_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {static_netplan_config} - {e}")
    
    # Parse INI file
    config = configparser.ConfigParser()
    config.read(config_ini_path)

    if "Wireless" not in config:
        log_message(f"ERROR: 'Wireless' section not found in {config_ini_path}.")
        # Unlink config file
        unlink_config_file_ini()
        return False

    # Read the /tmp/wireless.ini
    """
        [Wireless]
        ssid = <ssid>
        password = <password>
    """
    
    # Create DHCP netplan YAML if not available
    if not dhcp_netplan_config.exists():
        try:
            # Create DHCP netplan YAML
            dhcp_netplan_config.touch()
            dhcp_netplan_config.chmod(0o600)
            log_message(f"INFO: Created blank {dhcp_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to create {dhcp_netplan_config} - {e}")
            # Unlink config file
            unlink_config_file_ini()
            return False

        # Create DHCP netplan YAML content
        dhcp_yaml_content = {
            "network": {
                "version": 2,
                "renderer": "NetworkManager",
                "wifis":
                    {
                        interface: {
                            "dhcp4": True,
                            "optional": True,
                            "access-points": {
                                config.get("Wireless", "ssid"): {
                                    "password": config.get("Wireless", "password")
                                }
                            }
                        }
                    }
            }
        }

        # Write DHCP netplan YAML content
        with dhcp_netplan_config.open("w") as f:
            yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
            log_message(f"INFO: Wrote DHCP netplan YAML to {dhcp_netplan_config}.")
        return True

def unlink_config_file_ini():
    """Unlink the /tmp/wireless.ini file."""
    config_file_ini = Path("/tmp/wireless.ini")
    if config_file_ini.exists():
        try:
            config_file_ini.unlink()
            log_message(f"INFO: Unlinked {config_file_ini}.")
        except Exception as e:
            log_message(f"ERROR: Failed to unlink {config_file_ini} - {e}")
            return False
    return True
