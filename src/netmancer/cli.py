import argparse

def main():
    parser = argparse.ArgumentParser(prog='netmancer')
    subparsers = parser.add_subparsers()
    
    # Import and register subcommands
    from .commands.list_network import configure_parser as list_configure
    from .commands.scan_wireless_devices import configure_parser as wireless_configure
    
    list_configure(subparsers)
    wireless_configure(subparsers)
    
    # Add future commands here
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()