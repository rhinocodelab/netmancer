import subprocess
import json
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("/var/log/netmancer.log")

def log_message(message):
    """Write logs to /var/log/netmancer.log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    try:
        with LOG_FILE.open("a") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"ERROR: Writing to log file: {e}")

def configure_parser(subparsers):
    parser = subparsers.add_parser('status', help='Get the status of network interfaces')
    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='Get the status of given interface'
    )
    parser.set_defaults(func=handle_list)


def handle_list(args):
    interface = args.interface
    status = get_interface_status(interface)
    print(json.dumps(status, indent=2))

def get_interface_status(interface):
    """Get the status of the given status connected or disconnected"""
    # Check if the interface is connected
    try:
        subprocess.run(['ip', 'link', 'show', interface], check=True, capture_output=True)
        output = subprocess.run(['ip', 'link', 'show', interface], check=True, capture_output=True).stdout.decode().strip()
        if "state DOWN" in output:
            log_message(f"ERROR: Interface {interface} is not connected.")
            return False
        else:
            log_message(f"INFO: Interface {interface} is connected.")
            return True
    except subprocess.CalledProcessError:
        log_message(f"ERROR: Interface {interface} does not exist.")
        return False
