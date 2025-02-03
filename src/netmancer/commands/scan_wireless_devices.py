# src/netmancer/commands/scan_wireless_devices

import subprocess
import json
import re
from pathlib import Path

def configure_parser(subparsers):
    parser = subparsers.add_parser('scan-wifi', help='Scan for wireless devices')
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save output to specified JSON file'
    )
    parser.set_defaults(func=handle_wireless_devices)


def handle_wireless_devices(args):
    scanned_wifi_devices = scan_wireless_devices()
    if scanned_wifi_devices:
       if args.output:
           try:
               output_path = Path(args.output)
               # Ensure proper file extension
               if not output_path.suffix.lower() == '.json':
                   output_path = output_path.with_suffix('.json')
               output_path.write_text(json.dumps(scanned_wifi_devices, indent=4))
               print(f"Output saved to {output_path.resolve()}")
           except Exception as e:
               print(f"Error saving file: {str(e)}")
               raise SystemExit(1)
       else:
           print(json.dumps(scanned_wifi_devices, indent=4))
    else:
        print("No wireless devices found.")

def scan_wireless_devices():
    try:
        # Scan for wireless devices
        result = subprocess.run(
            ["nmcli", "-t", "-f", "BSSID,SSID,MODE,CHAN,RATE,SIGNAL,SECURITY", "dev", "wifi"],
            check=True,
            capture_output=True,
            text=True
            )
        wifi_list = []

        for line in result.stdout.strip().split("\n"):
            if line:
                fields = re.split(r'(?<!\\):', line)
                if len(fields) >= 7:
                    SSID = fields[1]
                    if SSID == "":
                        SSID = "Hidden Network"
                    wifi_list.append({
                        "BSSID": fields[0].replace("\\", ""),
                        "SSID": SSID,
                        "MODE": fields[2],
                        "CHAN": fields[3],
                        "RATE": fields[4],
                        "SIGNAL": fields[5],
                        "SECURITY": fields[6],
                    })
        return wifi_list
    except subprocess.CalledProcessError as e:
        print(f"Error scanning for wireless devices: {e}")
        return None
    except Exception as e:
        print(f"Error scanning for wireless devices: {e}")
        return None