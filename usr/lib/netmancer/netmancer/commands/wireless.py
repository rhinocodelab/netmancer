import subprocess
import yaml
import configparser
from pathlib import Path
from datetime import datetime


CONFIG_DIR = Path("/etc/netplan")
SYSCONF_DB = '/data/sysconf.db'
LOG_FILE = Path("/var/log/netmancer.log")
CONFIG_INI_PATH = Path("/tmp/wireless.ini")

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
    parser.add_argument(
        '--disable', '-x',
        action='store_true',
        help='Disable the Ethernet interface.'
    )
    parser.add_argument(
        '--access-point', '-a',
        nargs=2,
        metavar=('ACTION', 'SSID'),
        help='Enable or disable a specific access point. ACTION is "enable" or "disable", SSID is the access point name (e.g., "MyWiFi").'
    )

    parser.set_defaults(func=handle_wireless)

def handle_wireless(args):
    """Handles Wireless configuration based on user input."""
    if args.dhcp:
        log_message(f"INFO: Configuring DHCP for {args.interface}.")
        configure_dhcp(args.interface)
    elif args.static:
        log_message(f"INFO: Configuring static IP for {args.interface}.")
        configure_static(args.interface)
    elif args.disable:
        log_message(f"INFO: Disabling {args.interface}.")
        disable_wireless(args.interface)
    elif args.access_point:
        action, ssid = args.access_point
        log_message(f"INFO: {'Enabling' if action == 'enable' else 'Disabling'} access point '{ssid}' for {args.interface}.")
        manage_access_point(args.interface, ssid, action)
    else:
        log_message("ERROR: Invalid network configuration argument.")
        return False


def disable_wireless(interface):
    """Disables a Wireless interface."""
    dhcp_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-static.yaml"

    # Remove DHCP and static Netplan YAML if they exist
    if dhcp_netplan_config.exists():
        try:
            dhcp_netplan_config.unlink()
            log_message(f"INFO: Removed {dhcp_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {dhcp_netplan_config} - {e}")

    if static_netplan_config.exists():
        try:
            static_netplan_config.unlink()
            log_message(f"INFO: Removed {static_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {static_netplan_config} - {e}")

    # Bring down the interface
    try:
        subprocess.run(['nmcli', 'radio', 'wifi', 'off'], check=True)
        log_message(f"INFO: Interface {interface} is down.")
    except subprocess.CalledProcessError:
        log_message(f"ERROR: Failed to bring down interface {interface}.")
        return False
    return True


def configure_dhcp(interface):
    """Configure a Wireless interface with DHCP using /tmp/wireless.ini"""
    dhcp_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-static.yaml"

    # Remove STATIC Netplan YAML if it exists
    if static_netplan_config.exists():
        try:
            static_netplan_config.unlink()
            log_message(f"INFO: Removed {static_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to remove {static_netplan_config} - {e}")
    
    if not CONFIG_INI_PATH.exists():
        log_message(f"INFO: Configuration file {CONFIG_INI_PATH} not found.")
        return False
    
    # Parse INI file
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_PATH)

    if "Wireless" not in config:
        log_message(f"ERROR: 'Wireless' section not found in {CONFIG_INI_PATH}.")
        unlink_config_file_ini()
        return False

    # Read the /tmp/wireless.ini
    """
        [Wireless]
        ssid = <ssid>
        password = <password>
    """
    ssid = config.get("Wireless", "ssid")
    password = config.get("Wireless", "password")

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
                                ssid: {
                                    "password": password
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
    else:
        # YAML exists; check and update access-points
        log_message(f"INFO: {dhcp_netplan_config} already exists, checking SSID.")

        with dhcp_netplan_config.open("r") as f:
            dhcp_yaml_content = yaml.safe_load(f)
        
        # Ensure the structure exists
        if "network" not in dhcp_yaml_content or "wifis" not in dhcp_yaml_content["network"] or interface not in dhcp_yaml_content["network"]["wifis"]:
            log_message(f"ERROR: Invalid YAML structure in {dhcp_netplan_config}.")
            unlink_config_file_ini()
            return False
        
        # Get the Access-Points
        access_points = dhcp_yaml_content["network"]["wifis"][interface].get("access-points", {})

        if ssid not in access_points:
            # Add new SSID if not present
            access_points[ssid] = {"password": password}
            log_message(f"INFO: Added new SSID {ssid} to access-points in {dhcp_netplan_config}.")
            # Write the updated YAML
            with dhcp_netplan_config.open("w") as f:
                yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
                log_message(f"INFO: Updated DHCP netplan YAML in {dhcp_netplan_config}.")
        else:
            # SSID exists; check and update password
            if access_points[ssid].get("password") != password:
                access_points[ssid]["password"] = password
                log_message(f"INFO: Updated password for SSID {ssid} in {dhcp_netplan_config}.")
                # Write the updated YAML
                with dhcp_netplan_config.open("w") as f:
                    yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
                    log_message(f"INFO: Updated DHCP netplan YAML in {dhcp_netplan_config}.")
            else:
                log_message(f"INFO: SSID {ssid} and password already exist in {dhcp_netplan_config}.")
    # Apply NETPLAN
    if not apply_netplan():
        return False
    return True

def configure_static(interface):
    """Configure a Wireless interface with STATIC using /tmp/wireless.ini"""
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

    if not CONFIG_INI_PATH.exists():
        log_message(f"INFO: Configuration file {CONFIG_INI_PATH} not found.")
        return False
    
    # Parse INI file
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_PATH)

    if "Wireless" not in config:
        log_message(f"ERROR: 'Wireless' section not found in {CONFIG_INI_PATH}.")
        unlink_config_file_ini()
        return False
    
    """
        Get the below information:
        ssid, password, ip, subnet_mask, gateway, primary_dns, secondary_dns
    """
    ssid = config.get("Wireless", "ssid")
    password = config.get("Wireless", "password")
    ip = config.get("Wireless", "IP")
    subnet_mask = config.get("Wireless", "SubnetMask")
    gateway = config.get("Wireless", "Gateway", fallback="NA")
    primary_dns = config.get("Wireless", "PrimaryDNS", fallback="NA")
    secondary_dns = config.get("Wireless", "SecondaryDNS", fallback="NA")
    primary_wins = config.get("Wireless", "PrimaryWINS", fallback="NA")
    secondary_wins = config.get("Wireless", "SecondaryWINS", fallback="NA")

    if not static_netplan_config.exists():
        # Create new static YAML if does not exist
        try:
            static_netplan_config.touch()
            static_netplan_config.chmod(0o600)
            log_message(f"INFO: Created blank {static_netplan_config}.")
        except Exception as e:
            log_message(f"ERROR: Failed to create {static_netplan_config} - {e}")
            unlink_config_file_ini()
            return False
        
        static_yaml_content = {
            "network": {
                "version": 2,
                "renderer": "NetworkManager",
                "wifis": {
                    interface: {
                        "dhcp4": False,
                        "optional": True,
                        "access-points": {
                            ssid: {
                                "password": password
                            }
                        },
                        "addresses": [f"{ip}/{subnet_mask_to_cidr(subnet_mask)}"],
                        "routes": [{"to": "default", "via": gateway}]
                    }
                }
            }
        }
        nameservers = []
        if primary_dns != "NA":
            nameservers.append(primary_dns)
        if secondary_dns != "NA":
            nameservers.append(secondary_dns)
        if nameservers:
            static_yaml_content["network"]["wifis"][interface]["nameservers"] = {"addresses": nameservers}

        with static_netplan_config.open("w") as f:
            yaml.dump(static_yaml_content, f, default_flow_style=False)
            log_message(f"INFO: Wrote static netplan YAML to {static_netplan_config}.")
    else:
        # YAML exists; check and update access-points
        log_message(f"INFO: {static_netplan_config} already exists, checking SSID.")
        with static_netplan_config.open("r") as f:
            static_yaml_content = yaml.safe_load(f)
        if "network" not in static_yaml_content or "wifis" not in static_yaml_content["network"] or interface not in static_yaml_content["network"]["wifis"]:
            log_message(f"ERROR: Invalid YAML structure in {static_netplan_config}.")
            unlink_config_file_ini()
            return False
        # Get the Access-Points
        access_points = static_yaml_content["network"]["wifis"][interface].get("access-points", {})

        if ssid not in access_points:
            # Add new SSID if not present
            access_points[ssid] = {"password": password}
            log_message(f"INFO: Added new SSID {ssid} to access-points in {static_netplan_config}.")
            # Write the updated YAML
            with static_netplan_config.open("w") as f:
                yaml.dump(static_yaml_content, f, default_flow_style=False)
                log_message(f"INFO: Updated static netplan YAML in {static_netplan_config}.")
        else:
            # SSID exists; update password if different
            if access_points[ssid].get("password") != password:
                access_points[ssid]["password"] = password
                log_message(f"INFO: Updated password for SSID {ssid} in {static_netplan_config}.")
                # Write the updated YAML
                with static_netplan_config.open("w") as f:
                    yaml.dump(static_yaml_content, f, default_flow_style=False)
                    log_message(f"INFO: Updated static netplan YAML in {static_netplan_config}.")
            else:
                log_message(f"INFO: SSID {ssid} and password already exist in {static_netplan_config}.")
    
    if not apply_netplan():
        return False
    return True

def manage_access_point(interface, ssid, action):
    """Enable or disable a specific access point in the Netplan configuration."""
    dhcp_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"100-netmancer-{interface}-static.yaml"
    config_file = None

    # Determine which config file to modify (DHCP or Static)
    if dhcp_netplan_config.exists():
        config_file = dhcp_netplan_config
    elif static_netplan_config.exists():
        config_file = static_netplan_config
    else:
        log_message(f"ERROR: No DHCP or Static configuration found for {interface}.")
        return False
    
    # Load the YAML content
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    wifis = config.get('network', {}).get('wifis', {})

    for interface, settinfs in wifis.items():
        access_points = settinfs.get('access-points', {})

        for existing_ssid in list(access_points.keys()):
            if existing_ssid.lstrip("#") == ssid:
                ssid_key = existing_ssid.lstrip("#")
                ap_data = access_points.pop(existing_ssid)

                if action == "disable":
                    updated_ssid = f"# {ssid_key}"
                    if "password" in ap_data:
                        ap_data["# password"] = ap_data.pop("password")
                elif action == "enable":
                    updated_ssid = ssid_key
                    if "# password" in ap_data:
                        ap_data["password"] = ap_data.pop("# password")
                else:
                    log_message(f"ERROR: Invalid action '{action}' for SSID '{ssid}'.")
                    return False
                access_points[updated_ssid] = ap_data
            
    # Write the updated YAML content
    with open(config_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    # Apply the updated configuration
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
    config_file_ini = Path("/tmp/wireless.ini")
    try:
        config_file_ini.unlink(missing_ok=True)
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