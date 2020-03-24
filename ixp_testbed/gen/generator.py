"""Main functions of the topology generator."""

import bisect
from collections import defaultdict
import ipaddress
import logging
import os
from pathlib import Path
import sys
from typing import Any, Callable, DefaultDict, Dict, List, Mapping, MutableMapping, Optional, Tuple

from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
from lib.util import load_yaml_file
import yaml

import docker
from ixp_testbed import errors
from ixp_testbed.address import IfId, IpNetwork, L4Port, UnderlayAddress
import ixp_testbed.constants as const
from ixp_testbed.coordinator import Coordinator, User
import ixp_testbed.gen.addr_alloc as addr_alloc
import ixp_testbed.gen.gen_dir as gen_dir
from ixp_testbed.gen.interfaces import pick_unused_ifid
from ixp_testbed.host import Host, LocalHost, RemoteHost
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.network.docker import DockerBridge, OverlayNetwork
from ixp_testbed.network.host import HostNetwork
from ixp_testbed.network.ovs_bridge import OvsBridge
from ixp_testbed.scion import AS, BorderRouter, Link, LinkEp
from ixp_testbed.topology import Ixp, Topology
from ixp_testbed.util import crypto
from ixp_testbed.util.docker import copy_to_container, invoke_scion_docker_script, run_cmd_in_cntr

log = logging.getLogger(__name__)


def generate(name: Optional[str], input_file_path: Path, workdir: Path, sc: Path,
    dc: docker.DockerClient) -> Topology:
    """Generate a SCION topology from a topology definition.

    :param name: Optional name for the network. This name is used as a prefix for all Docker
                 objects and OVS bridges.
    :param input_file_path: Path to the topology definition file (YAML format).
    :param workdir: Directory in which the output files are written.
    :param sc: Path to the root of the SCION source tree.
    :param dc: Docker client object connected to the local Docker daemon.
    """
    # Process the topology file.
    topo_file = load_yaml_file(input_file_path)
    topo = extract_topo_info(topo_file, name)
    if topo.coordinator is None:
        # Create a topology file to be read by 'scion.sh topology'.
        processed_topo_file_path = workdir.joinpath(const.PROCESSED_TOPO_FILE)
        with open(processed_topo_file_path, 'w') as f:
            f.write(yaml.dump(topo_file))
        log.info("Wrote processed topology file to '%s'.", processed_topo_file_path)

    # Assign IP addresses in the coordinator network
    if topo.coordinator is not None:
        addr_alloc.assign_coord_ip_addresses(topo)

    # Assign BR interface IP addresses
    addr_alloc.check_subnet_overlap(topo)
    addr_alloc.assign_underlay_addresses(topo)

    # Make sure SCION images exists
    try:
        dc.images.get("scion_base")
    except docker.errors.ImageNotFound:
        log.info("SCION base image (scion_base) not found. Building...")
        invoke_scion_docker_script(sc, "base")
    try:
        dc.images.get("scion")
    except docker.errors.ImageNotFound:
        log.info("SCION image (scion) not found. Building...")
        invoke_scion_docker_script(sc, "build")

    if topo.coordinator is None:
        _build_docker_image(const.STANDALONE_TOPO_AS_IMG_NAME, "docker/as_standalone", dc)
        _build_standalone_topology(topo, sc, workdir, dc)
    else:
        _build_docker_image(const.COORD_TOPO_AS_IMG_NAME, "docker/as_with_coord", dc)
        _build_docker_image(const.COORD_IMG_NAME, "docker/coordinator", dc)
        _generate_coord_ssh_keys(topo, workdir)

    if topo.coordinator is None:
        # Modify topology.json files and create mount folder for all AS containers.
        gen_dir.modify_topo_files(workdir.joinpath(const.MASTER_CNTR_MOUNT, "gen"), topo)
        gen_dir.create_as_mount_dirs(workdir, topo)
    else:
        # Create mount folders for local ASes.
        # The AS configuration is downloaded from the coordinator when the containers are created.
        gen_dir.create_as_mount_dirs_coord(workdir, topo)
    log.info("Created mount folders.")

    return topo


def extract_topo_info(topo_file: MutableMapping[str, Any], name: Optional[str] = None) -> Topology:
    """Initialize a Topology object with information read from a topology definition.

    Interface identifiers not specified in the input file are automatically assigned and added to
    the returned Topology object and to `topo_file`.

    :param topo_file: The input topology file parsed into a dictionary. When the function returns,
                      the IXP testbed specific entries have been removed.
    :param name: An optional name for the topology. This name is added to all containers, network
                 bridges, etc. to distinguish them from other testbed instances.
    :returns: Extracted topology information.
    :raises InvalidTopo: The topology file is invalid.
    """
    topo = Topology(name)
    networks = NetworkFactory()
    brs = BrFactory()
    ifids = IfIdMapping(topo_file)

    # Subnet for automatically generated local docker bridges
    if 'link_subnet' in topo_file.get('defaults', {}):
        topo.default_link_subnet = ipaddress.ip_network(topo_file['defaults'].pop("link_subnet"))
        topo.ipv6_enabled |= (topo.default_link_subnet.version == 6)
    else:
        topo.default_link_subnet = None

    # Hosts (first pass: create host objects)
    localhost = topo.hosts['localhost'] = LocalHost() # always exists
    for host_name, host_def in topo_file.get('hosts', {}).items():
        if host_name != 'localhost':
            if host_name in topo.hosts:
                log.error("Multiple hosts with name '%s'.", host_name)
                raise errors.InvalidTopo()

            if not 'coordinator' in topo_file:
                log.error("Running a topology spanning multiple hosts requires a coordinator.")
                raise errors.InvalidTopo()

            topo.hosts[host_name] = RemoteHost(host_name,
                _get_ip(host_def, 'ssh_host', host_name),
                _get_value(host_def, 'username', host_name),
                identity_file=host_def.get("identity_file"),
                ssh_port=L4Port(int(host_def.get('ssh_port', 22))))

    # Networks
    if 'networks' in topo_file:
        net_defs = topo_file.pop('networks') # remove networks section
        for net_name, net_def in net_defs.items():
            type = _get_value(net_def, 'type', net_name)
            subnet = _get_value(net_def, 'subnet', net_name)
            host = topo.hosts[net_def.get('host', 'localhost')]
            networks.create(net_name, topo.get_name_prefix(), type, host, subnet, net_def)

    # Hosts (second pass: parse network addresses for host networks)
    for host_name, host_def in topo_file.get('hosts', {}).items():
            for net, addr in host_def.get('addresses', {}).items():
                networks.set_host_ip(net, topo.hosts[host_name], addr)
    topo_file.pop('hosts', None) # remove host section

    # Coordinator
    if 'coordinator' in topo_file:
        coord_def = topo_file.pop('coordinator') # remove coordinator section
        host = topo.hosts[coord_def.get('host', 'localhost')]
        def_name = lambda: topo.get_name_prefix() + const.COORD_NET_NAME
        bridge = networks.get(_get_value(coord_def, 'network', 'coordinator'), def_name, localhost)
        coord = Coordinator(host, bridge)

        if 'expose' in coord_def:
            ip = ipaddress.ip_address(coord_def.get('expose_on', '0.0.0.0'))
            port = L4Port(int(coord_def['expose']))
            coord.exposed_at = UnderlayAddress(ip, port)

        for name, data in coord_def['users'].items():
            if name is None:
                log.error("User name missing.")
                raise errors.InvalidTopo()
            coord.users[name] = User(data['email'], data['password'], data.get('superuser', False))

        topo.coordinator = coord

    # IXP definitions
    for ixp_name, ixp_def in topo_file.pop('IXPs', {}).items(): # remove IXP section
        if ixp_name in topo.ixps:
            log.error("IXP %s is defined multiple times.", name)
            raise errors.InvalidTopo()
        net_name = _get_value(ixp_def, 'network', ixp_name)
        def_name = lambda: topo.get_name_prefix() + ixp_name
        bridge = networks.get(net_name, def_name, localhost)
        topo.ixps[ixp_name] = Ixp(bridge)

    # ASes
    for as_name, as_def in topo_file['ASes'].items():
        isd_as = ISD_AS(as_name)
        host_name = as_def.get('host', 'localhost')
        host = None
        try:
            host = topo.hosts[host_name]
        except KeyError:
            log.error("Invalid host: '%s'.", as_def[host_name])
            raise
        asys = AS(host, as_def.get('core', False))

        asys.is_attachment_point = as_def.pop('attachment_point', False)
        asys.owner = as_def.pop('owner', None)
        topo.ases[isd_as] = asys

        if topo.coordinator:
            for ixp_name in as_def.pop('ixps', []):
                if asys.owner is None:
                    log.error("Infrastructure AS %s has an IXP list.", isd_as)
                    raise errors.InvalidTopo()
                ixp = topo.ixps[ixp_name]
                ixp.ases[isd_as] = asys
                # Add dummy link to IXP to make sure there is a network connection.
                # Actual links will be configured by the coordinator.
                # The border router of the link endpoint is labeled here to avoid creating a new
                # border router for every IXP link.
                end_point = LinkEp.Construct(isd_as, ifid=ifids.assign_ifid(isd_as), br_label='peer')
                link = Link(end_point, LinkEp(), LinkType.UNSET)
                link.bridge = ixp.bridge
                topo.links.append(link)
                brs.add_link_ep(end_point, link)

    # Link definitions
    for link in topo_file['links']:
        a, b = LinkEp(link['a']), LinkEp(link['b'])

        # Assing IfIds if not given in the original topo file.
        # Setting the IDs of all interfaces in the processed topology file ensures we can identify
        # the interfaces in the configuration files generated by scion.sh.
        for ep, name in [(a, 'a'), (b, 'b')]:
            if ep.ifid is None:
                ep.ifid = ifids.assign_ifid(ep)
                link[name] = "{}#{}".format(link[name], ep.ifid)

        topo.links.append(Link(a, b, link['linkAtoB']))

        # Keep track of border routers that will be created for the links.
        brs.add_link_ep(a, topo.links[-1])
        brs.add_link_ep(b, topo.links[-1])

        # Assign to a network if an IXP name or an explicit IP network is given.
        if "network" in link:
            net = link.pop('network')
            if net in topo.ixps: # use the IXPs network
                ixp = topo.ixps[net]
                topo.links[-1].bridge = ixp.bridge
                ixp.ases[a] = topo.ases[a]
                ixp.ases[b] = topo.ases[b]
            else:
                def_name = lambda: topo.gen_bridge_name()
                topo.links[-1].bridge = networks.get(net, def_name, localhost)
        else:
            if topo.ases[a].host != topo.ases[b].host:
                log.error("Links between ASes on different hosts must specify the network to use.")
                raise errors.InvalidTopo()

    # Enable IPv6 support if needed.
    topo.ipv6_enabled = networks.is_ipv6_required()

    # Store bridges in topology.
    topo.bridges = networks.get_bridges()

    # Store border router info in corresponsing AS.
    for isd_as, asys in topo.ases.items():
        asys.border_routers = brs.get_brs(isd_as)

    return topo


def _get_value(dict, key, name):
    try:
        return dict[key]
    except KeyError:
        log.error("'%s' is missing from '%s'.", key, name)
        raise


def _get_ip(dict, key, name):
    raw = _get_value(dict, key, name)
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        log.error("Invalid IP address in '%s': '%s'.", name, raw)
        raise


class NetworkFactory:
    """Helper class for creating network bridges.

    :ivar _bridges: Bridges created so far. Maps from name in the topology file to bridge instance.
    :ivar _detected_ipv6: Whether any bridge requires IPv6 support.
    """
    def __init__(self):
        self._bridges: Dict[str, Bridge] = {}
        self._detected_ipv6 = False

    def create(self, name: str, name_prefix: str, type: str, host: Host, subnet_str: str,
        options: Mapping[str, Any]) -> Bridge:
        """Create a new network bridge.

        :param name: Name of the new network.
        :param name_prefix: Name prefix of the topology.
        :param type: Type of the new network. One of 'docker_bridge', 'ovs_bridge', 'overlay' or
                     'host'.
        :param host: The host which is supposed to manage the bridge.
        :param subnet_str: The IP subnet for the network as a string to be parsed and validated.
        :param options: Additional options for creating the bridge.
        :returns: The newly created bridge.
        :raises InvalidTopo: Parameter validation failed.
        """
        if name in self._bridges:
            log.error("Multiple networks with name '%s'.", name)
            raise errors.InvalidTopo()

        subnet = self._parse_ip_network(subnet_str)
        bridge = None
        if type == 'docker_bridge':
            bridge = DockerBridge(name_prefix + name, host, subnet)
        elif type == 'ovs_bridge':
            bridge = OvsBridge(name_prefix + name, host, subnet)
        elif type == 'overlay':
            bridge = OverlayNetwork(name_prefix + name, host, subnet,
                encrypted=options.get('encrypted', False))
        elif type == 'host':
            bridge = HostNetwork(name_prefix + name, subnet)
        else:
            log.error("Unknown network type '%s'.", type)
            raise errors.InvalidTopo()

        self._detected_ipv6 |= (subnet.version == 6)
        self._bridges[name] = bridge
        return bridge

    def set_host_ip(self, net_name: str, host: Host, ip: str) -> None:
        """Notify a network bridge about the IP address of a host.

        :param net_name: Name of the network in which to set the host IP. Must be of type 'host'.
        :param ip: IP address of the host as string to be parsed and validated.
        :raises InvalidTopo: Parameter validation failed.
        """
        bridge = self._bridges.get(net_name)
        if bridge is None or not isinstance(bridge, HostNetwork):
            log.error("Must be a valid host network: '%s'.", net_name)
            raise errors.InvalidTopo()
        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            log.error("Invalid IP address: '%s'.", ip)
            raise errors.InvalidTopo()
        else:
            bridge.set_host_ip(host, ip_addr)

    def get(self, name: str, def_name: Callable[[], str], localhost: LocalHost) -> Bridge:
        """Returns a bridge previously created by create() or creates a default bridge.

        If no bridge called `name` exists, a new DockerBridge is created is created on localhost.

        :param name: Name to look up.
        :param def_name: Callable generating a name for the default bridge if necessary.
        :param localhost: Needed to created the default bridge.
        """
        bridge = self._bridges.get(name)
        if bridge is not None:
            return bridge
        else:
            try:
                subnet = ipaddress.ip_network(name)
            except ValueError:
                log.error("Not a network name or IP subnet: '%s'.", name)
                raise
            else:
                # If an IP subnet is specified directly, create a local Docker bridge.
                bridge = DockerBridge(def_name(), localhost, subnet)
                self._detected_ipv6 |= (subnet.version == 6)
                self._bridges[name] = bridge
                return bridge

    def get_bridges(self) -> List[Bridge]:
        """Retuns the list of all generated bridges."""
        return list(self._bridges.values())

    def is_ipv6_required(self):
        """Returns whether the topology must support IPv6."""
        return self._detected_ipv6

    @staticmethod
    def _parse_ip_network(subnet: str) -> IpNetwork:
        try:
            return ipaddress.ip_network(subnet)
        except ValueError:
            log.error("Invalid IP network: '%s'.", subnet)
            raise errors.InvalidTopo()


class BrFactory:
    """Helper class for creating `BorderRouter` objects.

    :ivar _border_routers: Map of AS identifier to its border routers.
    """
    def __init__(self):
        BrList = List[BorderRouter]
        BrNameMap = DefaultDict[str, BorderRouter]
        BorderRouters = DefaultDict[ISD_AS, Tuple[BrList, BrNameMap]]
        self._border_routers: BorderRouters = defaultdict(lambda: ([], {}))

    def add_link_ep(self, link_ep: LinkEp, link: Link) -> None:
        """Assign the given link to a `BorderRouter` object identified by `link_ep`.

        This function assigns IDs to border routers in the same way as the SCION topology generator
        does: IDs are assigned consecutively starting from 1. Border routers, which have not been
        given a name in the topology file have a single interface, i.e., a new BR is created with
        the next available ID for every link added to the AS.
        Border routers that have a name can have multiple interfaces, and are given an ID the first
        time they are encountered.

        Border routers are named in the topology definition by inserting a name between the ISD-AS
        identifer and the interface ID. For example, "1-ff00:0:110-test#1" names interface "1" of a
        BR called "test" in ASff00:0:110.
        """
        unnamed_brs, named_brs = self._border_routers[link_ep]
        nextId = len(unnamed_brs) + len(named_brs) + 1
        br_name = link_ep.br_name()
        if br_name:
            if br_name not in named_brs:
                named_brs[br_name] = BorderRouter(nextId)
            named_brs[br_name].links[IfId(link_ep.ifid)] = link
        else:
            unnamed_brs.append(BorderRouter(nextId))
            unnamed_brs[-1].links[IfId(link_ep.ifid)] = link

    def get_brs(self, isd_as: ISD_AS) -> List[BorderRouter]:
        """Returns the list of `BorderRouters`s belonging to the given AS."""
        unnamed, named = self._border_routers[isd_as]
        return unnamed + list(named.values())


class IfIdMapping:
    """Helper class keeping track of assigned interface identifers per AS."""

    def __init__(self, topo_file: MutableMapping[str, Any]):
        """Initializes used interface identifier sets from the given topology file."""
        self.used_ifids: DefaultDict[ISD_AS, List[IfId]] = defaultdict(list)
        for link in topo_file['links']:
            for ep in [LinkEp(link['a']), LinkEp(link['b'])]:
                if ep.ifid:
                    self.used_ifids[ep].append(IfId(ep.ifid))

        for ifids in self.used_ifids.values():
            ifids.sort()


    def assign_ifid(self, isd_as: ISD_AS) -> IfId:
        """Returns an unused ifid in the given AS and marks it as used for future calls."""
        ifid = pick_unused_ifid(self.used_ifids[isd_as])
        bisect.insort_left(self.used_ifids[isd_as], ifid)
        return ifid


def _build_docker_image(image_name: str, build_path: str, dc: docker.DockerClient):
    """Builds a Docker image if it does not exist.

    :param image_name: Name of the image to build.
    :param build_path: Path to the directory containing the Dockerfile.
    :param dc: Docker client the image is build with.
    :raises docker.errors.BuildError:
    """
    try:
        dc.images.get(image_name)
    except docker.errors.ImageNotFound:
        log.info("Image '%s' not found. Building...", image_name)
        try:
            dc.images.build(
                path=str(Path(sys.path[0]).joinpath(build_path)),
                tag=image_name, rm=True)
        except docker.errors.BuildError:
            log.error("Building image '%s' failed.", image_name)
            raise


def _build_standalone_topology(topo: Topology, sc: Path, workdir: Path, dc: docker.DockerClient):
    """Build a standalone SCION topology using the 'scion.sh' script."""

    # Start master container
    master_cntr_name = topo.get_name_prefix() + const.MASTER_CNTR_NAME
    log.info("Starting SCION Docker container.")
    invoke_scion_docker_script(sc, "start", {
        'SCION_CNTR': master_cntr_name,
        'SCION_IMG': const.STANDALONE_TOPO_AS_IMG_NAME,
        'SCION_MOUNT': workdir.joinpath(const.MASTER_CNTR_MOUNT).resolve() # need absolute path
    })

    master_cntr = dc.containers.get(master_cntr_name)
    try:
        # Copy processed topology file into the master container
        processed_topo_file_path = workdir.joinpath(const.PROCESSED_TOPO_FILE)
        copy_to_container(master_cntr, processed_topo_file_path, const.SCION_TOPO_FILES_PATH)

        # Build a standalone topology in the master container
        log.info("Building standalone topology...")
        command = "./scion.sh topology nobuild -c topology/topology.topo"
        if topo.ipv6_enabled:
            command += " --ipv6"
        run_cmd_in_cntr(master_cntr, const.SCION_USER, command, check=True)
    except:
        raise
    finally:
        master_cntr.stop()
        master_cntr.remove()


def _generate_coord_ssh_keys(topo: Topology, workdir: Path):
    """Generate an SSH key pair and client configuration for the coordinator.

    The keys and configuration file are stored in the `workdir`/ssh.
    """
    log.info("Generating SSH keys.")
    private, public = crypto.generate_ssh_key_pair()
    output_path = workdir.joinpath(const.COORD_KEY_PATH)

    os.mkdir(output_path)
    with open(output_path.joinpath(const.COORD_PRIVATE_KEY_FILE), 'wb') as file:
        file.write(private)
    with open(output_path.joinpath(const.COORD_PUBLIC_KEY_FILE), 'wb') as file:
        file.write(public)

    with open(output_path.joinpath(const.SSH_CLIENT_CONFIG), 'w') as config:
        for isd_as in topo.ases.keys():
            config.write("Host %s\n" % topo.coordinator.bridge.get_ip_address(isd_as))
            config.write("    User %s\n" % const.SCION_USER)
            config.write("    IdentityFile ~/scionlab/run/coord_id_rsa\n")
            # Supported since OpenSSH 7.6:
            # automatically accept host keys on first connection
            # config.write("    StrictHostKeyChecking accept-new\n")