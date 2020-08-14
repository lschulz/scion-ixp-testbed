"""Implementation of commands called from the command line interface."""

import json
import logging
import sys

import docker
from lib.errors import SCIONParseError

from ixp_testbed.address import ISD_AS
from ixp_testbed.constants import CONFIG_DATA_FILE
from ixp_testbed.run.exec import fetch_config, run_in_cntrs
import ixp_testbed.run.links as links
from ixp_testbed.run.stats import Measurements, measure_perf_stats
from ixp_testbed.topology import Topology
from ixp_testbed.util.log import open_log_file

log = logging.getLogger(__name__)


def start(args):
    """Start the containers and SCION."""
    open_log_file(args.workdir)
    log.debug("Command: start")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))

    try:
        # Make sure the containers are running
        topo.create_bridges()
        topo.start_containers(workdir=args.workdir, sc=args.sc, push_images=args.push_images)
        # Run SCION in containers
        if args.mode == 'sequential':
            topo.run_scion()
        elif args.mode == 'parallel':
            topo.run_scion_parallel()
        elif args.mode == 'detach':
            topo.run_scion_parallel(detach=True)
    finally:
        topo.close_host_connections()
        topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def start_cntrs(args):
    """Start the containers and the coordinator if applicable."""
    open_log_file(args.workdir)
    log.debug("Command: start_cntrs")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))

    try:
        topo.create_bridges()
        topo.start_containers(workdir=args.workdir, sc=args.sc, push_images=args.push_images)
    finally:
        topo.close_host_connections()
        topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def stop(args):
    """Stop SCION, but keep the containers and the coordinator running."""
    open_log_file(args.workdir)
    log.debug("Command: stop")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))

    try:
        if args.mode == 'sequential':
            topo.stop_scion()
        elif args.mode == 'parallel':
            topo.stop_scion_parallel()
        elif args.mode == 'detach':
            topo.stop_scion_parallel(detach=True)
    finally:
        topo.close_host_connections()
        topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def stop_cntrs(args):
    """Stop all containers."""
    open_log_file(args.workdir)
    log.debug("Command: stop_cntrs")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))

    try:
        topo.stop_containers()
        topo.remove_bridges()
    finally:
        topo.close_host_connections()
        topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def status(args):
    """Get status information on the SCION services from supervisord."""
    # Don't log this command. Does not change state.
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    topo.print_container_status()


def exec(args):
    """Run a command in one or multiple containers."""
    open_log_file(args.workdir)
    log.debug("Command: exec")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    try:
        run_in_cntrs(topo, as_selector=args.as_pattern,
            cmd_template=args.command, user=args.user,
            detach=args.detach, dry_run=args.dry_run)
    finally:
        topo.close_host_connections()


def update(args):
    """Fetch the AS configuration files from the coordinator."""
    open_log_file(args.workdir)
    log.debug("Command: update")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    try:
        if topo.coordinator is None:
            log.error("Topology has no coordinator.")
        else:
            if args.as_list is None:
                fetch_config(topo, as_selector=args.as_pattern, detach=args.detach,
                    force=args.force, no_restart=args.no_restart, rate=args.rate)
            else:
                as_list = []
                with open(args.as_list) as file:
                    for line in file.readlines():
                        as_list.append(ISD_AS(line))
                fetch_config(topo, as_selector=as_list, detach=args.detach,
                    force=args.force, no_restart=args.no_restart, rate=args.rate)
    finally:
        topo.close_host_connections()


def stats(args):
    """Measure the average CPU utilization of SCION ASes and services."""
    open_log_file(args.workdir)
    log.debug("Command: stats")
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    try:
        measurements = Measurements()
        # Read existing measurements.
        try:
            with open(args.output_file) as file:
                measurements.data = json.load(file)
        except FileNotFoundError:
            pass # No existing data to read in.

        # Take new measurements and merge with existing data.
        measurements.experiment = args.experiment
        measure_perf_stats(topo, measurements,
            as_pattern=args.as_pattern, services=set(args.services),
            interval=args.interval, count=args.count)

        # Write merged data back to disk.
        with open(args.output_file, 'w') as file:
            json.dump(measurements.data, file)

    finally:
        topo.close_host_connections()


def policy(args):
    """Wrapper around the coordinator's peering policy REST API."""
    open_log_file(args.workdir)
    log.debug("Command: policy %s" % args.action)
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))

    # Parse and validate ISD-AS string.
    try:
        isd_as = ISD_AS(args.isd_as)
    except SCIONParseError:
        log.error("Invalid ISD-AS string.")
        return
    try:
        if not topo.ases[isd_as].is_user_as():
            log.error("'%s' is not a user AS.", isd_as)
            return
    except KeyError:
        log.error("Unknown AS: %s", isd_as)
        return

    try:
        if topo.coordinator is None:
            log.error("Topology has no coordinator.")
        else:
            response = None
            if args.action == "get_peers":
                response = topo.coordinator.get_peers(isd_as, args.ixp)
            elif args.action == "get":
                response = topo.coordinator.get_policies(isd_as, args.ixp)
            elif args.action == "create":
                policies = sys.stdin.read() if args.data is None else args.data
                print(topo.coordinator.create_policies(isd_as, policies))
            elif args.action == "delete":
                policies = sys.stdin.read() if args.data is None else args.data
                print(topo.coordinator.delete_policies(isd_as, policies))

            if response is not None:
                print(json.dumps(response, indent=2))

    finally:
        topo.close_host_connections()


def list_links(args):
    """List all links this script has created in the topology.

    Links created by the coordinator are not listed.
    """
    # Don't log this command. Does not change state.
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    try:
        links.print_links(topo)
    finally:
        topo.close_host_connections()


def add_link(args):
    """Add a link to the topology."""
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    link = _get_link_from_args(topo, args)

    if link is not None:
        ixp, as_a, as_b = link
        open_log_file(args.workdir)
        log.debug("Command: add_link")

        try:
            links.add_link(topo=topo, workdir=args.workdir, dc=docker.from_env(),
                ixp=ixp, a=(args.as_a, as_a), b=(args.as_b, as_b),
                link_properties={
                    "type": args.type,
                    "mtu": args.mtu,
                    "bandwidth": args.bandwidth
                })
        finally:
            topo.close_host_connections()
            topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def modify_link(args):
    """Modify an existing link."""
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    link = _get_link_from_args(topo, args)

    if link is not None:
        ixp, as_a, as_b = link
        properties = {}
        arg_dict = vars(args)

        for key in ['type', 'mtu', 'bandwidth']:
            if key in arg_dict:
                properties[key] = arg_dict[key]

        open_log_file(args.workdir)
        log.debug("Command: modify_link")

        try:
            links.modify_link(topo=topo, workdir=args.workdir, dc=docker.from_env(),
                ixp=ixp, a=(args.as_a, as_a), b=(args.as_b, as_b),
                link_properties=properties)
        finally:
            topo.close_host_connections()
            topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def remove_link(args):
    """Remove a link from the topology."""
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    link = _get_link_from_args(topo, args)

    if link is not None:
        ixp, as_a, as_b = link
        open_log_file(args.workdir)
        log.debug("Command: remove_link")
        try:
            links.remove_link(topo=topo, workdir=args.workdir, dc=docker.from_env(),
                ixp=ixp, a=(args.as_a, as_a), b=(args.as_b, as_b))
        finally:
            topo.close_host_connections()
            topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def _get_link_from_args(topo: Topology, args):
    """Get the IXP and ASes identified by the command line arguments in `args` for adding, removing
    or modifying a link.

    :returns: `None` if the IXP or ASes were not found or are not valid for link modifications.
              Otherwise a tuple of the IXP, the first and the second AS of the link.
    """
    def get_or_print(d, key, error_msg):
        try:
            return d[key]
        except KeyError:
            print(error_msg())
            return None

    ixp = get_or_print(topo.ixps, args.ixp, lambda: "Unknown IXP: " + args.ixp)
    as_a = get_or_print(topo.ases, args.as_a, lambda: "Unknown AS: " + str(args.as_a))
    as_b = get_or_print(topo.ases, args.as_b, lambda: "Unknown AS: " + str(args.as_b))

    if ixp is None or as_a is None or as_b is None:
        return None

    if not as_a.host.is_local or not as_b.host.is_local:
        print("ASes must run on localhost.")
        return None

    return ixp, as_a, as_b
