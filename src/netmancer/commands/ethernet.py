# src/netmancer/commands/ethernet.py

import configparser
import subprocess
import yaml
from pathlib import Path
from datetime import datetime

def configure_parser(subparsers):
    parser = subparsers.add_parser('ethernet', help='Configure Ethernet using netplan')
    parser.add_argument(
        'ini_file_path',
        type=str,
        help='Path to ethernet.ini configuration file'
    )
    parser.add_argument(
        '--apply', '-a',
        action='store_true',
        help='Immediately apply the configuration'
    )
    parser.set_defaults(func=handle_configure)

def handle_configure(args):
    # Read and parse INI file
    config = read_ini_config(args.ini_file_path)
    
    # Generate netplan YAML
    yaml_config = generate_netplan_yaml(config)
    
    # Create netplan filename
    #netplan_file = f"/etc/netplan/99-network-manager-{datetime.now().strftime('%Y%m%d%H%M%S')}.yaml"
    netplan_file = f"99-network-manager-{datetime.now().strftime('%d%m%Y:%H%M')}.yaml"
    # netplan_file = f"99-network-manager-{datetime.now().strftime('%Y%m%d%H%M%S')}.yaml"
    
    try:
        # Write YAML config
        Path(netplan_file).write_text(yaml.dump(yaml_config, default_flow_style=False))
        print(f"Netplan configuration written to {netplan_file}")
        
        if args.apply:
            apply_netplan()
            
    except PermissionError:
        print("Error: Requires sudo privileges to write to /etc/netplan/")
        raise SystemExit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        raise SystemExit(1)

def read_ini_config(file_path):
    """Parse and validate the INI configuration file"""
    config = configparser.ConfigParser()
    config.read(file_path)
    
    if 'ethernet' not in config:
        raise ValueError("Missing [ethernet] section in configuration file")
    
    eth_config = config['ethernet']
    required = ['device', 'dhcp']
    for field in required:
        if field not in eth_config:
            raise ValueError(f"Missing required field: {field}")
    
    if eth_config.getboolean('dhcp') and 'addresses' in eth_config:
        raise ValueError("Cannot specify both dhcp=true and static addresses")
    
    if not eth_config.getboolean('dhcp'):
        static_required = ['addresses', 'gateway4']
        for field in static_required:
            if field not in eth_config:
                raise ValueError(f"Static configuration requires {field}")
    
    return eth_config

def generate_netplan_yaml(config):
    """Generate netplan YAML structure"""
    dhcp = config.getboolean('dhcp')
    device = config['device']
    
    yaml_config = {
        'network': {
            'version': 2,
            'renderer': 'NetworkManager',
            'ethernets': {
                device: {}
            }
        }
    }
    if dhcp:
        yaml_config['network']['ethernets'][device].update({
            'dhcp4': True,
            'optional': True
        })
        return yaml_config
    else:
        # Read netmask and convert to CIDR notation
        netmask = config['netmask']
        cidr = subnet_mask_to_cidr(netmask)
        if cidr is None:
            raise ValueError("Invalid subnet mask")
        yaml_config['network']['ethernets'][device].update({
            'addresses': [f"{config['addresses']}/{cidr}"],
            'routes': [{'to': 'default', 'via': config['gateway4']}],
            'nameservers': {
                'addresses': [dns.strip() for dns in config.get('dns', '').split(',') if dns.strip()]
            }
        })
    
    return yaml_config

def apply_netplan():
    """Apply netplan configuration"""
    try:
        subprocess.run(
            ['sudo', 'netplan', 'apply'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("Configuration applied successfully")
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply configuration: {e.stderr.decode()}")
        raise SystemExit(1)

def subnet_mask_to_cidr(mask):
    """Convert subnet mask to CIDR notation"""
    try:
        # Split the subnet mask into octets and validate
        octets = mask.split('.')
        if len(octets) != 4:
            raise ValueError("Invalid subnet mask format")

        # Convert octets to binary and count the number of 1s
        binary_representation = ''.join(f"{int(octet):08b}" for octet in octets)
        cidr = binary_representation.count('1')

        # Check if the subnet mask is valid
        if '01' in binary_representation:  # Invalid subnet masks will have mixed 1s and 0s
            raise ValueError("Invalid subnet mask value")

        return cidr
    except Exception as e:
        print(f"Error: {e}")
        return None