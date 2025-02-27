import subprocess
from pathlib import Path
from datetime import datetime
import configparser

LOG_FILE = Path("/var/log/netmancer.log")
DNS_INI_FILE = Path("/tmp/dns.ini")
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
    dns_parser = subparsers.add_parser('dns', help='Configure DNS settings')
    dns_parser.add_argument('config_ini_path', type=str, help='Path to the configuration INI file')
    dns_parser.set_defaults(func=dns_command)

def dns_command(args):
    """Configure DNS settings based on the provided INI file."""
    
    config_ini_path = Path(args.config_ini_path)

    if not config_ini_path.exists():
        log_message(f"ERROR: Configuration INI file not found at {config_ini_path}.")
        return False

    config = configparser.ConfigParser()
    config.read(config_ini_path)

    if not config.has_section('DNS') or not config.has_option('DNS', 'dns_servers'):
        log_message("ERROR: Missing [DNS] section or dns_servers option in INI file.")
        return False

    dns_servers = config.get('DNS', 'dns_servers').strip()

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

    # Process `dns_servers=NA` (Remove only DNS and FallbackDNS keys)
    if dns_servers.upper() == "NA":
        log_message("INFO: Removing global DNS configuration while keeping the rest of the file.")

        # Remove only DNS and FallbackDNS entries
        new_lines = [line for line in lines if not line.strip().startswith(("DNS=", "FallbackDNS="))]

        try:
            with GLOBAL_RESOLVE_CONF.open("w") as f:
                f.writelines(new_lines)

            log_message("INFO: Updated /etc/systemd/resolved.conf (Removed DNS entries).")

            # Restart systemd-resolved
            subprocess.run(['systemctl', 'restart', 'systemd-resolved'], check=True)
            log_message("INFO: Restarted systemd-resolved.")
        except Exception as e:
            log_message(f"ERROR: Failed to update DNS settings: {e}")
            return False

        return True

    # Process normal DNS configuration
    dns_list = dns_servers.split(',')
    primary_dns = dns_list[0]
    fallback_dns = " ".join(dns_list[1:]) if len(dns_list) > 1 else ""

    log_message(f"INFO: Setting primary DNS: {primary_dns}")
    if fallback_dns:
        log_message(f"INFO: Setting fallback DNS: {fallback_dns}")

    # Remove old DNS entries while keeping other settings
    new_lines = [line for line in lines if not line.strip().startswith(("DNS=", "FallbackDNS="))]
    new_lines.append(f"DNS={primary_dns}\n")
    if fallback_dns:
        new_lines.append(f"FallbackDNS={fallback_dns}\n")

    try:
        with GLOBAL_RESOLVE_CONF.open("w") as f:
            f.writelines(new_lines)

        log_message("INFO: Updated /etc/systemd/resolved.conf.")

        # Restart systemd-resolved
        subprocess.run(['systemctl', 'restart', 'systemd-resolved'], check=True)
        log_message("INFO: Restarted systemd-resolved.")
    except Exception as e:
        log_message(f"ERROR: Failed to update DNS settings: {e}")
        return False

    return True
