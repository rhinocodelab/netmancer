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
    """Configures the command-line argument parser for Ethernet settings."""
    parser = subparsers.add_parser('ethernet', help='Configure Ethernet interface')
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

    parser.set_defaults(func=handle_ethernet)

def handle_ethernet(args):
    """Handles Ethernet configuration based on user input."""
    if not (args.dhcp or args.static or args.disable):
        log_message("Error: Missing network configuration argument --dhcp or --static or --disable.")
        return False

    if args.dhcp:
        configure_dhcp(args.interface, args.dhcp)
    elif args.static:
        configure_static(args.interface, args.static)
    elif args.disable:
        disable_ethernet(args.interface)
    else:
        log_message("Error: Invalid network configuration argument.")
        return False

def disable_ethernet(interface):
    """Disables an Ethernet interface."""
    dhcp_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-static.yaml"

    # Check if the interface exists in the system
    try:
        subprocess.run(['ip', 'link', 'show', interface], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        log_message(f"ERROR: Interface {interface} does not exist.")
        return False

    # Check if the interface is already down
    try:
        subprocess.run(['ip', 'link', 'show', interface], check=True, capture_output=True)
        output = subprocess.run(['ip', 'link', 'show', interface], check=True, capture_output=True).stdout.decode().strip()
        if "state DOWN" in output:
            log_message(f"INFO: Interface {interface} is already down.")
            return True
    except subprocess.CalledProcessError:
        log_message(f"ERROR: Interface {interface} does not exist.")
        return False

    # Bring the interface down
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        log_message(f"INFO: Interface {interface} is down.")
        # Remove DHCP netplan YAML if it exists
        if dhcp_netplan_config.exists():
            try:
                dhcp_netplan_config.unlink()
                log_message(f"INFO: Removed {dhcp_netplan_config}.")
            except Exception as e:
                log_message(f"ERROR: Failed to remove {dhcp_netplan_config} - {e}")
        # Remove static netplan YAML if it exists
        if static_netplan_config.exists():
            try:
                static_netplan_config.unlink()
                log_message(f"INFO: Removed {static_netplan_config}.")
            except Exception as e:
                log_message(f"ERROR: Failed to remove {static_netplan_config} - {e}")
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"ERROR: Failed to bring {interface} down - {e}")
        return False

def configure_dhcp(interface, config_ini_path):
    """Configures an Ethernet interface with DHCP."""
    dhcp_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-static.yaml"

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

    if "Ethernet" not in config:
        log_message(f"ERROR: 'Ethernet' section not found in {config_ini_path}.")
        # Unlink config file
        unlink_config_file_ini()
        return False
    
    # Read the /tmp/ethernet.ini
    """
        [Ethernet]
        dns = true
        PrimaryDNS = NA
        SecondaryDNS = NA
    """
    # Get the bool value for dns
    extra1 = 0
    dns = config.getboolean("Ethernet", "dns")
    if dns:
        extra1 = 1
    # Get the PrimaryDNS value
    primary_dns = config.get("Ethernet", "PrimaryDNS")
    # Get the SecondaryDNS value
    secondary_dns = config.get("Ethernet", "SecondaryDNS")

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
                "ethernets": {
                    interface: {
                        "dhcp4": True,
                        "optional": True
                    }
                }
            }
        }
        # Add DNS servers to the YAML content if PrimaryDNS or SecondaryDNS is not 'NA'
        if primary_dns != 'NA':
            dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"] = {"addresses": [primary_dns]}
        if secondary_dns != 'NA':
            if "nameservers" not in dhcp_yaml_content["network"]["ethernets"][interface]:
                dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"] = {"addresses": []}
            dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"]["addresses"].append(secondary_dns)
        
        # Write DHCP netplan YAML content
        with dhcp_netplan_config.open("w") as f:
            yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
            log_message(f"INFO: Wrote DHCP netplan YAML to {dhcp_netplan_config}.")
        
        # Apply NETPLAN
        if not apply_netplan(interface, 2, extra1):
            return False
        return True
    else:
        log_message(f"INFO: {dhcp_netplan_config} already exists.")
        # If PrimaryDNS or SecondaryDNS is available then update the dhcp_yaml_content
        if primary_dns != 'NA' or secondary_dns != 'NA':
            try:
                with dhcp_netplan_config.open("r") as f:
                    dhcp_yaml_content = yaml.safe_load(f)
                    if primary_dns != 'NA':
                        dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"] = {"addresses": [primary_dns]}
                    if secondary_dns != 'NA':
                        if "nameservers" not in dhcp_yaml_content["network"]["ethernets"][interface]:
                            dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"] = {"addresses": []}
                        dhcp_yaml_content["network"]["ethernets"][interface]["nameservers"]["addresses"].append(secondary_dns)
                with dhcp_netplan_config.open("w") as f:
                    yaml.dump(dhcp_yaml_content, f, default_flow_style=False)
                    log_message(f"INFO: Updated DHCP netplan YAML in {dhcp_netplan_config}.")
            except Exception as e:
                log_message(f"ERROR: Failed to update DHCP netplan YAML - {e}")
                # Unlink config file
                unlink_config_file_ini()
                return False
        # Apply NETPLAN
        if not apply_netplan(interface, 2, extra1):
            return False
        return True

def configure_static(interface, config_ini_path):
    """Configures an Ethernet interface with STATIC."""
    dhcp_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-dhcp.yaml"
    static_netplan_config = CONFIG_DIR / f"99-netmancer-{interface}-static.yaml"
    
    # Remove DHCP yaml if available
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
    
    if "Ethernet" not in config:
        log_message(f"ERROR: 'Ethernet' section not found in {config_ini_path}.")
        # Unlink config file
        unlink_config_file_ini()
        return False
    
    # Get PrimaryDNS, SecondaryDNS, PrimwaryWINS and SecondaryWINS values
    primary_dns = config.get("Ethernet", "PrimaryDNS")
    secondary_dns = config.get("Ethernet", "SecondaryDNS")
    primary_wins = config.get("Ethernet", "PrimaryWINS")
    secondary_wins = config.get("Ethernet", "SecondaryWINS")

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
            "ethernets": {
                interface: {
                    "dhcp4": False,
                    "optional": True,
                    "addresses": [ f'{config.get("Ethernet", "IP")}/{subnet_mask_to_cidr(config.get("Ethernet", "SubnetMask"))}' ],
                    "routes": [{
                        "to": "default",
                        "via": config.get("Ethernet", "Gateway")
                    }],
                    "nameservers": {
                        "addresses": [primary_dns]
                    }
                }
            }
        }
    }
    # Add SecondaryDNS to the YAML content if it is not 'NA'
    if secondary_dns != 'NA':
        static_yaml_content["network"]["ethernets"][interface]["nameservers"]["addresses"].append(secondary_dns)
    # Add PrimaryWINS to the YAML content if it is not 'NA'
    if primary_wins != 'NA':
        static_yaml_content["network"]["ethernets"][interface]["nameservers"]["addresses"].append(primary_wins)
    # Add SecondaryWINS to the YAML content if it is not 'NA'
    if secondary_wins != 'NA':
        static_yaml_content["network"]["ethernets"][interface]["nameservers"]["addresses"].append(secondary_wins)

    # Write STATIC netplan yaml content
    with static_netplan_config.open("w") as f:
        yaml.dump(static_yaml_content, f, default_flow_style=False)
        log_message(f"INFO: Wrote STATIC netplan YAML to {static_netplan_config}.")

    # Apply NETPLAN
    if not apply_netplan(interface, 1, 0):
        return False
    return True

def apply_netplan(interface, networkmode, extra1):
    """Apply NETPLAN YAML"""
    try:
        subprocess.run(["netplan", "apply"], check=True)
        log_message("INFO: NETPLAN applied successfully.")
        if not update_db(interface, networkmode, extra1):
            # Unlink config file
            unlink_config_file_ini()
            return False
        # Unlink config file
        unlink_config_file_ini()
        return True
    except subprocess.CalledProcessError as e:
        log_message(f"ERROR: Failed to apply NETPLAN - {e}")
        # Unlink config file
        unlink_config_file_ini()
        return False


def update_db(interface, networkmode, extra1):
    # Check if 'NetworkDetails' table is available
    try:
        conn = sqlite3.connect(SYSCONF_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='NetworkDetails'")
        table_exists = cursor.fetchone()
        if not table_exists:
            log_message("INFO: NetworkDetails table not found. Creating table...")
            # Create NetworkDetails table
            cursor.execute("""
                CREATE TABLE NetworkDetails(
                    NetworkMode INTEGER,
                    IP VARCHAR(40),
                    Subnetmask VARCHAR(50),
                    Gateway VARCHAR(50),
                    PrimaryWIN VARCHAR(50),
                    SecondaryWIN VARCHAR(50),
                    PrimaryDNS VARCHAR(50),
                    SecondaryDNS VARCHAR(50),
                    LinkMode VARCHAR(40),
                    Speed VARCHAR(50),
                    WakeOn VARCHAR(30),
                    NetworkType VARCHAR(30) PRIMARY KEY,
                    Extra1 INTEGER,
                    Extra2 INTEGER,
                    Extra3 INTEGER,
                    Extra4 VARCHAR(30),
                    Extra5 VARCHAR(30)
                )
            """)
            conn.commit()
            log_message("INFO: NetworkDetails table created successfully")
        
            # Update the 'NetworkDetails' table
            cursor.execute("""
                UPDATE NetworkDetails 
                SET NetworkMode = ?, LinkMode = ?, WakeOn = ?, Extra1 = ?
                WHERE NetworkType = ?
            """,(networkmode,'Auto select' 'g', extra1,interface))
            conn.commit()
        else:
            # Update the 'NetworkDeatils' table
            cursor.execute("""
                UPDATE NetworkDetails
                SET NetworkMode = ?, Extra1 = ?
                WHERE NetworkType = ?
            """,(networkmode, extra1, interface))
            conn.commit()
        conn.close()
        log_message("INFO: NetworkDetails table updated successfully.")
        return True
    except Exception as e:
        log_message(f"Error: Updating NetworkDetails table: {e}")
        return False
    finally:
        conn.close()

def unlink_config_file_ini():
    """Unlink the /tmp/ethernet.ini file."""
    config_file_ini = Path("/tmp/ethernet.ini")
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