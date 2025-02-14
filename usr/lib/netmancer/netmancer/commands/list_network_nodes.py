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
        save_output(args.output, interfaces)
    else:
        print(json.dumps(interfaces, indent=4))


def save_output(output_path_str, data):
    try:
        output_path = Path(output_path_str)
        
        # Ensure proper file extension
        if not output_path.suffix.lower() == '.json':
            output_path = output_path.with_suffix('.json')
        
        # Create parent directories if they don't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        output_path.write_text(json.dumps(data, indent=4))
        print(f"Output saved to {output_path.resolve()}")
    except PermissionError:
        print("ERROR: Insufficient permissions to save the file.")
        raise SystemExit(1)
    except Exception as e:
        print(f"ERROR: An error occurred while saving file: {str(e)}")
        raise SystemExit(1)


def get_interfaces():
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device', 'status'],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        return {
            "error": "Error running nmcli",
            "details": e.stderr.strip()
        }
    except FileNotFoundError:
        return {
            "error": "Command not found",
            "details": "Ensure 'nmcli' is installed along with NetworkManager."
        }

    interfaces = []
    for line in result.stdout.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[1] not in ('loopback'):
            interfaces.append({
                'interface': parts[0],
                'type': parts[1],
                'state': parts[2],
                'connection': parts[3] if len(parts) > 3 else ''
            })

    if not interfaces:
        return {
            "error": "No active network interfaces found"
        }
        
    return interfaces
