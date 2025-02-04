import argparse
from .commands.ethernet import configure_parser as ethernet_configure
def main():
    parser = argparse.ArgumentParser(prog='netmancer')
    subparsers = parser.add_subparsers()
    
    # Import and register subcommands
    from .commands.list_network import configure_parser as list_configure
    from .commands.scan_wireless_devices import configure_parser as scan_wireless
    from .commands.ethernet import configure_parser as ethernet_configure
    
    list_configure(subparsers)
    scan_wireless(subparsers)
    ethernet_configure(subparsers)
    
    # Add future commands here
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()