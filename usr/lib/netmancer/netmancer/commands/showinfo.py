import subprocess
from pathlib import Path
from datetime import datetime
import json

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
    """Configures the command-line argument parser for showinfo."""
    parser = subparsers.add_parser('showinfo', help='Show network information about the given device interface')
    parser.add_argument('--interface', '-i', required=True, help='Ethernet interface name (e.g., eth0)')
    parser.set_defaults(func=handle_showinfo)

def handle_showinfo(args):
    """Handles the showinfo command."""
    # Get the interface name from the command-line argument
    interface = args.interface
    # Get the interface details
    interface_details = get_interface_details(interface)
    # Print the interface details
    if interface_details:
        print(json.dumps(interface_details, indent=4))
    else:
        print(f"Interface {interface} is not connected.")

def get_interface_details(interface):
    """
        Get the interface details from the nmcli
        The output will be in JSON format with below details
    """
    try:
        """Get network interface details using nmcli."""
        result = subprocess.run(["nmcli", "--terse", "--fields", "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,GENERAL.STATE", "device", "show", interface],
                                capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split("\n")

        if not any("connected" in line for line in lines):
            log_message(f"ERROR: Interface {interface} is not connected.")
            return {}

        details = {}
        for line in lines:
            key, value = line.split(":", 1)
            if "IP4.ADDRESS" in key:
                ip, cidr = value.split("/")
                details['IP'] = ip
                details['Subnetmask'] = cidr_to_subnet(cidr)
            elif key == "IP4.GATEWAY":
                details['Gateway'] = value
            elif "IP4.DNS" in key:
                details.setdefault('Nameserver', []).append(value)
            
            # Get speed and duplex and wake-on using ethtool
            try:
                ethtool_output = subprocess.run(["ethtool", interface], capture_output=True, text=True, check=True).stdout
                for line in ethtool_output.split("\n"):
                    if "Speed" in line:
                        details['Speed'] = line.split(":")[1].strip()
                    elif "Duplex" in line:
                        details['Duplex'] = line.split(":")[1].strip()
                    elif "Wake-on" in line:
                        details['Wake-on'] = line.split(":")[1].strip()
            except subprocess.CalledProcessError:
                log_message(f"Error: Getting ethtool details: {e}")
                details['Speed'] = "NA"
                details['Duplex'] = "NA"
                details['Wake-on'] = "NA"
        details['Interface'] = interface
        return details
    except Exception as e:
        log_message(f"Error: Getting interface details: {e}")
        return {}



def cidr_to_subnet(cidr):
    """Convert CIDR prefix length to subnet mask."""
    bits = 0xffffffff ^ (1 << 32 - int(cidr)) - 1
    return '.'.join(str((bits >> (i * 8)) & 0xff) for i in reversed(range(4)))