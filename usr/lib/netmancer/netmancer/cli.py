import argparse

def main():
    parser = argparse.ArgumentParser(prog="netmancer")
    subparsers = parser.add_subparsers()

    # Import and configure each command
    from netmancer.commands.list_network_nodes import configure_parser as list_network_nodes_parser
    from netmancer.commands.ethernet import configure_parser as ethernet_parser
    from netmancer.commands.showinfo import configure_parser as showinfo_parser
    from netmancer.commands.wireless import configure_parser as wireless_parser
    from netmancer.commands.status import configure_parser as status_parser
    from netmancer.commands.dhcpinfo import configure_parser as dhcpinfo_parser
    from netmancer.commands.dns import configure_parser as dns_parser
    from netmancer.commands.dns_suffix import configure_parser as dns_suffix_parser

    list_network_nodes_parser(subparsers)
    ethernet_parser(subparsers)
    showinfo_parser(subparsers)
    wireless_parser(subparsers)
    status_parser(subparsers)
    dhcpinfo_parser(subparsers)
    dns_parser(subparsers)
    dns_suffix_parser(subparsers)           
    
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()