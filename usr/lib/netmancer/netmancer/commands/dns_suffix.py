import subprocess
from pathlib import Path
from datetime import datetime
import configparser

LOG_FILE = Path("/var/log/netmancer.log")
DNS_SUFFIX_INI_FILE = Path("/tmp/dns_suffix.ini")
GLOBAL_RESOLVE_CONF = Path("/etc/systemd/resolved.conf")

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
    """
        Configure the subparser for the 'dns' command.
        Pass /tmp/dns.ini as argument to the command.
    """
    dns_parser = subparsers.add_parser('dnssuffix', help='Configure DNS Suffix settings')
    dns_parser.add_argument('config_ini_path', type=str, help='Path to the configuration INI file')
    dns_parser.set_defaults(func=dns_suffix_command)

def dns_suffix_command(args):
    """Configure DNS search domain based on the provided INI file."""
    config_ini_path = Path(args.config_ini_path)

    if not config_ini_path.exists():
        log_message(f"ERROR: Configuration file {config_ini_path} does not exist.")
        return False
    
    config = configparser.ConfigParser()
    config.read(config_ini_path)

    if not config.has_section('SUFFIX') or not config.has_option('SUFFIX','dns_suffix'):
        log_message("ERROR: Missing [SUFFIX] section or dns_suffix option in INI file.")
        return False
    
    dns_suffix = config.get('SUFFIX', 'dns_suffix').strip()

    # Ensure /etc/systemd/resolved.conf exists
    if not GLOBAL_RESOLVE_CONF.exists():
        log_message("WARNING: /etc/systemd/resolved.conf not found. Creating a new one.")
        try:
            with GLOBAL_RESOLVE_CONF.open("w") as f:
                f.write("[Resolve]\n")
            log_message("INFO: Created /etc/systemd/resolved.conf.")
        except Exception as e:
            log_message(f"ERROR: Failed to create /etc/systemd/resolved.conf: {e}")
            return False

    # Read existing resolved.conf content
    with GLOBAL_RESOLVE_CONF.open("r") as f:
        lines = f.readlines()

    # If dns_suffix=NA, remove "Domains=" entry but keep the rest of the file
    if dns_suffix.upper() == "NA":
        log_message("INFO: Removing DNS suffix (Domains=) while keeping the rest of the file.")

        # Remove only Domains entry
        new_lines = [line for line in lines if not line.strip().startswith("Domains=")]

        try:
            with GLOBAL_RESOLVE_CONF.open("w") as f:
                f.writelines(new_lines)

            log_message("INFO: Updated /etc/systemd/resolved.conf (Removed Domains entry).")

            # Restart systemd-resolved
            subprocess.run(['systemctl', 'restart', 'systemd-resolved'], check=True)
            log_message("INFO: Restarted systemd-resolved.")
        except Exception as e:
            log_message(f"ERROR: Failed to update DNS suffix settings: {e}")
            return False

        return True

    # Process normal DNS suffix configuration
    domains = dns_suffix.split(',')
    formatted_domains = " ".join(domains)

    log_message(f"INFO: Setting DNS search domains: {formatted_domains}")

    # Remove old Domains entry while keeping other settings
    new_lines = [line for line in lines if not line.strip().startswith("Domains=")]
    new_lines.append(f"Domains={formatted_domains}\n")

    try:
        with GLOBAL_RESOLVE_CONF.open("w") as f:
            f.writelines(new_lines)

        log_message("INFO: Updated /etc/systemd/resolved.conf.")

        # Restart systemd-resolved
        subprocess.run(['systemctl', 'restart', 'systemd-resolved'], check=True)
        log_message("INFO: Restarted systemd-resolved.")
    except Exception as e:
        log_message(f"ERROR: Failed to update DNS suffix settings: {e}")
        return False

    return True
