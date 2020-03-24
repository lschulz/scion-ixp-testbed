#!/usr/bin/python3
import argparse
import logging
import os
import sys
from pathlib import Path

from lib.packet.scion_addr import ISD_AS

import ixp_testbed.run.commands
import ixp_testbed.gen.commands
from ixp_testbed.constants import DEFAULT_LINK_BW, DEFAULT_LINK_TYPE, DEFAULT_MTU, SCION_USER


def create_parser() -> argparse.ArgumentParser:
    """Returns an ArgumentParser configured with the programs command line parameters."""
    parser = argparse.ArgumentParser()
    add_common_arguments(parser)
    subparsers = parser.add_subparsers()

    # topology subcommand
    topo_parser = subparsers.add_parser("topology", help="Generate a local topology.")
    topo_parser.add_argument('topo_file', type=Path, help="Topology configuration file.")
    topo_parser.add_argument('--clear-workdir', action='store_true',
        help="Clear the work directory if not empty.")
    topo_parser.add_argument('-n', '--name',
        help="Prefix to add to all Docker containers and images created by the command. Default: No prefix.",
        default=None)
    topo_parser.set_defaults(exec_subcommand=ixp_testbed.gen.commands.generate_topology)

    # start subcommand
    start_parser = subparsers.add_parser("start", help="Start the network.")
    group = start_parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--sequential", action='store_const', const='sequential', dest='mode',
        help="Start ASes (not containers) sequentially one after the other.")
    group.add_argument("-p", "--parallel", action='store_const', const='parallel', dest='mode',
        help="Start ASes (not containers) in parallel. This is the default.")
    group.add_argument("-d", "--detach", action='store_const', const='detach', dest='mode',
        help="Begin starting all ASes (not containers) in the background and return as soon as possible."
             " Does not log AS output, but is faster then '-s' and '-p'. Also avoids issues with too"
             " many open SSH connections that '-p' might have.")
    start_parser.set_defaults(mode='parallel', exec_subcommand=ixp_testbed.run.commands.start)

    # stop subcommand
    stop_parser = subparsers.add_parser("stop", help="Stop a running network, but not the containers and networks.")
    group = stop_parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--sequential", action='store_const', const='sequential', dest='mode',
        help="Stop ASes sequentially one after the other.")
    group.add_argument("-p", "--parallel", action='store_const', const='parallel', dest='mode',
        help="Stop ASes in parallel. This is the default.")
    group.add_argument("-d", "--detach", action='store_const', const='detach', dest='mode',
        help="Begin stopping all ASes in the background and return as soon as possible."
             " Does not log AS output, but is faster then '-s' and '-p'. Also avoids issues with too"
             " many open SSH connections that '-p' might have.")
    stop_parser.set_defaults(mode='parallel', exec_subcommand=ixp_testbed.run.commands.stop)

    # status subcommand
    status_parser = subparsers.add_parser("status", help="Print the network status.")
    status_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.status)

    # exec subcommand
    exec_parser = subparsers.add_parser("exec", help="Execute a command in AS containers.")
    exec_parser.add_argument("as_pattern",
        help="Regular expression matched against AS identifiers. Command is executed in all matching ASes.")
    exec_parser.add_argument("command",
        help="The command to execute. ISD-AS string is substituted for '{isd_as}' and '{file_fmt}'.")
    exec_parser.add_argument("-u", metavar="user", dest='user',
        help="User to execute the command as. Default: '{}'".format(SCION_USER),
        default=SCION_USER)
    exec_parser.add_argument("-d", action='store_true', dest='detach',
        help="Detach command from Docker exec. Not output is forwarded.")
    exec_parser.add_argument("-n", action='store_true', dest='dry_run',
        help="Just print what would be executed.")
    exec_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.exec)

    # update subcommand
    update_parser = subparsers.add_parser("update",
        help="Update the AS with a new configuration from the coordinator.")
    update_parser.add_argument("-p", dest='as_pattern', default='.*',
        help="Regular expression matched against AS identifiers. Only matching ASes are updated."
             " Default: All ASes.")
    update_parser.add_argument("-d", action='store_true', dest='detach',
        help="Do not wait for updates to complete. Not output is forwarded.")
    update_parser.add_argument("-f", action='store_true', dest='force',
        help="Install the configuration from the coordinator even if the AS appears to be up to date.")
    update_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.update)

    # policy subcommand
    policy_parser = subparsers.add_parser("policy",
        help="Get, add, and delete policies using the coordinator's REST API.")
    policy_parser.add_argument("action", choices=["get_peers", "get", "create", "delete"],
        help="The request to perform.")
    policy_parser.add_argument("isd_as",
        help="ISD-AS string identifying the user AS whose peering policies to manage.")
    policy_parser.add_argument("--ixp", type=int,
        help="For 'get_peers' and 'get'. Filter for the given IXP id.")
    policy_parser.add_argument("--data", help="Policy data in JSON format."
        " Only for 'create' and 'delete'. If not specified data is read from stdin.")
    policy_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.policy)

    # stats subcommand
    stats_parser = subparsers.add_parser("stats",
        help="Take performance measurements.")
    stats_parser.add_argument("-p", dest='as_pattern', default='.*',
        help="Regular expression matched against AS identifiers. Measurements are made only in matching ASes."
             " Default: All ASes.")
    stats_parser.add_argument("--services", metavar="executable", nargs='*', default=[],
        help="List of SCION executables (bin/border, bin/beacon_srv, etc.) to record separate statists for."
             " By default only AS level statistics are returned.")
    stats_parser.add_argument("-i", dest='interval', type=float, default=60.0,
        help="Time interval to take measurements over in seconds. Default: 60")
    stats_parser.add_argument("-c", dest="count", type=int, default=1,
    help="The number of measurements to take. Default: 1")
    stats_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.stats)

    # cntrs subcommand
    cntrs_parser = subparsers.add_parser("cntrs",
        help="Manage Docker containers.")
    cntrs_parser.add_argument("command", choices=["start", "stop"])
    cntrs_parser.set_defaults(exec_subcommand=cntrs_command)

    # link subcommand
    link_parser = subparsers.add_parser("link", help="Manage SCION links.")
    link_subparsers = link_parser.add_subparsers()
    list_link_parser = link_subparsers.add_parser("list")
    list_link_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.list_links)

    add_link_parser = link_subparsers.add_parser("add",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help="Add a new link.")
    add_common_link_args(add_link_parser)
    add_link_parser.add_argument("--type", choices=["PARENT", "CHILD", "PEER", "CORE"], default=DEFAULT_LINK_TYPE,
        help="Link type")
    add_link_parser.add_argument("--bandwidth", type=int, default=DEFAULT_LINK_BW,
        help="Link bandwidth")
    add_link_parser.add_argument("--mtu", type=int, default=DEFAULT_MTU,
        help="MTU")
    add_link_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.add_link)

    modify_link_parser = link_subparsers.add_parser("modify",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help="Modify an existing link.")
    add_common_link_args(modify_link_parser)
    modify_link_parser.add_argument("--type", choices=["PARENT", "CHILD", "PEER", "CORE"], default=DEFAULT_LINK_TYPE,
        help="Link type")
    modify_link_parser.add_argument("--bandwidth", type=int, default=DEFAULT_LINK_BW,
        help="Link bandwidth")
    modify_link_parser.add_argument("--mtu", type=int, default=DEFAULT_MTU,
        help="MTU")
    modify_link_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.modify_link)

    remove_link_parser = link_subparsers.add_parser("remove", help="Remove a link.")
    add_common_link_args(remove_link_parser)
    remove_link_parser.set_defaults(exec_subcommand=ixp_testbed.run.commands.remove_link)

    # plot subcommand
    plot_parser = subparsers.add_parser("plot",
        help="Print a graph description in graphviz dot syntax illustrating the topology.")
    plot_parser.set_defaults(exec_subcommand=ixp_testbed.gen.commands.plot)

    return parser


def add_common_arguments(parser):
    """Add the command lines parameters common to all subcommand to the given parser."""
    parser.add_argument('-w', '--workdir', type=Path,
        help="Working directory of the network. Default: 'network-gen'",
        default="network-gen")
    parser.add_argument('--sc', type=Path,
        help="Path to the root of the SCION source tree. Default: $SC",
        default=os.environ.get('SC', ""))
    parser.set_defaults(exec_subcommand=lambda args: parser.print_usage())


def add_common_link_args(parser):
    """Add common parameters of the add, modify and remove link commands."""
    parser.add_argument("ixp",
        help="IXP the link is established over.")
    parser.add_argument(metavar="AS1", dest='as_a', type=ISD_AS,
        help="First AS of the link.")
    parser.add_argument(metavar="AS2", dest='as_b', type=ISD_AS,
        help="Second AS of the link.")


def init_logging():
    # Print messages of level INFO and above to the console.
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.addFilter(logging.Filter("ixp_testbed"))
    log.addHandler(handler)


def cntrs_command(args):
    if args.command == "start":
        ixp_testbed.run.commands.start_cntrs(args)
    elif args.command == "stop":
        ixp_testbed.run.commands.stop_cntrs(args)


def link_command(args):
    if args.command == "add":
        ixp_testbed.run.commands.add_link(args)
    elif args.command == "remove":
        ixp_testbed.run.commands.remove_link(args)


def main():
    parser = create_parser()
    args = parser.parse_args()
    args.exec_subcommand(args)


if __name__ == "__main__":
    init_logging()
    main()
