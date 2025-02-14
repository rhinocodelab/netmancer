import subprocess
import yaml
import configparser
from pathlib import Path
from datetime import datetime


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

    parser.add_argument(
        '--static', '-s',
        metavar="CONFIG_FILE",
        help='Configure static IP. Provide the path to the INI configuration file.'
    )

    parser.set_defaults(func=handle_wireless)

def handle_wireless(args):
    """Handles Wireless configuration based on user input."""
    if args.dhcp:
        configure_dhcp(args.interface, args.dhcp)
    elif args.static:
        configure_static(args.interface, args.static)
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
        
        # Apply NETPLAN
        if not apply_netplan():
            return False
        return True
    else:
        log_message(f"INFO: {dhcp_netplan_config} already exists.")
        # Check if ssid or password is updated
        with dhcp_netplan_config.open("r") as f:
            dhcp_yaml_content = yaml.safe_load(f)
            if dhcp_yaml_content["network"]["wifis"][interface]["access-points"][config.get("Wireless", "ssid")]["password"] != config.get("Wireless", "password"):
                # Update the YAML content
                dhcp_yaml_content["network"]["wifis"][interface]["access-points"][config.get("Wireless", "ssid")]["password"] = config.get("Wireless", "password")
                # Write updated YAML content
                with dhcp_netplan_config.open("w") as f:
                    yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
                    log_message(f"INFO: Updated DHCP netplan YAML in {dhcp_netplan_config}.")
            else:
                log_message(f"INFO: No changes detected in {dhcp_netplan_config}.")
        # Apply NETPLAN
        if not apply_netplan():
            return False
        return True

def configure_static(interface, config_ini_path):
    """Configure an Wireless interface with STATIC"""
    dhcp_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-static.yaml"

    # Remove DHCP Netplan YAML if it exists
    if dhcp_netplan_config.exists():
        try:
            dhcp_netplan_config.unlink()
            log_message(f"INFO: Removed {dhcp_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {dhcp_netplan_config} - {e}")
            return False

    # Remove STATIC yaml if available
    if static_netplan_config.exists():
        try:
            static_netplan_config.unlink()
            log_message(f"INFO: Removed {static_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {static_netplan_config} - {e}")
            return False
        
    # Parse INI file
    config = configparser.ConfigParser()
    config.read(config_ini_path)

    if "Wireless" not in config:
        log_message(f"ERROR: 'Wireless' section not found in {config_ini_path}.")
        # Unlink config file
        unlink_config_file_ini()
        return False
    
    # Get PrimaryDNS, SecondaryDNS, PrimwaryWINS and SecondaryWINS values
    primary_dns = config.get("Wireless", "PrimaryDNS")
    secondary_dns = config.get("Wireless", "SecondaryDNS")
    primary_wins = config.get("Wireless", "PrimaryWINS")
    secondary_wins = config.get("Wireless", "SecondaryWINS")

    # Create STATIC netplan yaml
    try:
        # Create STATIC netplan yaml
        static_netplan_config.touch()
        static_netplan_config.chmod(0o600)
        log_message(f"INFO: Created blank {static_netplan_config}.")
    except Exception as e:
        log_message(f"ERROR: Failed to create {static_netplan_config} - {e}")
        # Unlink config file
        unlink_config_file_ini()
        return False
    
    # Create STATIC netplan yaml content
    static_yaml_content = {
        "network": {
            "version": 2,
            "renderer": "NetworkManager",
            "wifis": {
                interface: {
                    "dhcp4": False,
                    "optional": True,
                    "access-points": {
                        config.get("Wireless", "ssid"): {
                            "password": config.get("Wireless", "password")
                        }
                    },
                    "addresses": [ f'{config.get("Wireless", "IP")}/{subnet_mask_to_cidr(config.get("Wireless", "SubnetMask"))}' ],
                    "routes": [{
                        "to": "default",
                        "via": config.get("Wireless", "Gateway")
                    }],
                    
                }
            }
        }
    }
    nameservers = []
    if primary_dns != 'NA':
        nameservers.append(primary_dns)
    if secondary_dns != 'NA':
        nameservers.append(secondary_dns)
    if nameservers:
        static_yaml_content["network"]["wifis"][interface]["nameservers"] = {"addresses": nameservers}
        
    # Write STATIC netplan yaml content
    with static_netplan_config.open("w") as f:
        yaml.dump(static_yaml_content, f, default_flow_style=False)
        log_message(f"INFO: Wrote STATIC netplan YAML to {static_netplan_config}.")

    # Apply NETPLAN
    if not apply_netplan():
        return False
    return True



def apply_netplan():
    """Apply NETPLAN YAML"""
    try:
        result = subprocess.run(["netplan", "apply"], check=True)
        if result.returncode == 0:
            log_message("INFO: NETPLAN applied successfully.")
        else:
            log_message("ERROR: NETPLAN failed to apply.")
            return False
        # Unlink config file
        unlink_config_file_ini()
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"ERROR: Failed to apply NETPLAN - {e}")
        # Unlink config file
        unlink_config_file_ini()
        return False

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


def subnet_mask_to_cidr(mask):
    """Convert subnet mask to CIDR prefix length."""
    try:
        # Split the mask into octets and count the bits set to 1
        return sum(bin(int(octet)).count('1') for octet in mask.split('.'))
    except ValueError:
        print("Invalid subnet mask format.")
        return None