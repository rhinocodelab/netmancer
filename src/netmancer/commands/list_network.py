# src/netmancer/commands/list.py

import subprocess
import json
from pathlib import Path

def configure_parser(subparsers):
    parser = subparsers.add_parser('list', help='List network interfaces')
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save output to specified JSON file'
    )
    parser.set_defaults(func=handle_list)

def handle_list(args):
    interfaces = get_interfaces()
    if args.output:
        try:
            output_path = Path(args.output)
            # Ensure proper file extension
            if not output_path.suffix.lower() == '.json':
                output_path = output_path.with_suffix('.json')
            output_path.write_text(json.dumps(interfaces, indent=4))
            print(f"Output saved to {output_path.resolve()}")
        except Exception as e:
            print(f"Error saving file: {str(e)}")
            raise SystemExit(1)
    else:
        print(json.dumps(interfaces, indent=4))

def get_interfaces():
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device', 'status'],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running nmcli: {e.stderr}")
        return []
    except FileNotFoundError:
        print("Error: nmcli command not found. Ensure NetworkManager is installed.")
        return []

    interfaces = []
    for line in result.stdout.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[1] != 'loopback':
            interfaces.append({
                'interface': parts[0],
                'type': parts[1],
                'state': parts[2],
                'connection': parts[3] if len(parts) > 3 else ''
            })

    return interfaces
