"""Class representing a SCIONLab coordinator and types and functions supporting its configuration.
"""

import io
import json
import logging
from pathlib import Path
from typing import Dict, NamedTuple, Optional, Tuple

import docker
from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType

from ixp_testbed import constants as const
from ixp_testbed.address import IfId, L4Port, UnderlayAddress
from ixp_testbed.host import Host
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS, Link
from ixp_testbed.util.docker import copy_to_container, run_cmd_in_cntr
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


class User:
    """User account for the SCIONLab coordinator.

    :ivar email: Email address of the user.
    :ivar password: Account password.
    :ivar is_admin: Whether the account has superuser privileges.
    """
    def __init__(self, email: str, password: str, is_admin: bool = False):
        self.email = email
        self.password = password
        self.is_admin = is_admin


class ApiCredentials(NamedTuple):
    """Credentails for the coordinator's REST API."""
    uid: str
    secret: str


class Coordinator:
    """Contains information on an instance of the SCIONLab coordinator.

    :ivar host: Host running the coordinator.
    :ivar bridge: Network for communication with ASes.
    :ivar exposed_at: Host address to expose the coordinator on.
    :ivar container_id: ID of the Docker container running the coordinator.
    :ivar users: Mapping from user name to user data. The user name is only used by this script.
                 The coordinator identifies users by their email address.
    :ivar api_credentials: Coordinator API credentials for all ASes.
    :ivar _initialized: Flag indicating whether the coordinator has been initialized.
    """
    def __init__(self, host: Host, bridge: Bridge):
        self.host = host
        self.bridge = bridge
        self.exposed_at: Optional[UnderlayAddress] = None
        self.container_id: Optional[str] = None
        self.users: Dict[str, User] = {}
        self.api_credentials: Dict[ISD_AS, ApiCredentials]
        self._initialized = False


    def init(self, topo, workdir: Path):
        """Initialize the coordinators database.

        Checks it the coordinator needs initialization. If it does, the coordinators's database is
        populated with the topology definition and the data needed for automatic AS deployment is
        exchanged.
        """
        assert topo.coordinator is self
        if not self._initialized:
            config_ssh_client(topo, workdir)
            init_db(topo, workdir)
            fetch_api_secrets(topo)
            self._initialized = True


    def get_container(self):
        """Get the container the coordinator is running in if `self.container_id` is not None.

        :raises docker.errors.NotFound: If Docker could not find the container.
        """
        return self.host.docker_client.containers.get(self.container_id)


    def start(self, cntr_name: str) -> None:
        """Start the coordinator in its own container.

        :param cntr_name: Name of the coordinator's container.
        """
        dc = self.host.docker_client

        # Check wheather the coordinator is already running
        if self.container_id:
            try:
                cntr = dc.containers.get(self.container_id)
            except docker.errors.NotFound:
                self.container_id = None
            else:
                if cntr.status == 'running':
                    return # coordinator is already running
                else:
                    # Remove old container
                    cntr.stop()
                    cntr.remove()

        # Expose coordinator on host interface
        ports = {}
        if self.exposed_at is not None:
            external_ip, external_port = self.exposed_at
            ports['%d/tcp' % const.COORD_PORT] = (str(external_ip), int(external_port))
            log.info("Exposing coordinator at http://%s", self.exposed_at.format_url())

        # Create and run the container
        cntr = dc.containers.run(const.COORD_IMG_NAME,
            name=cntr_name,
            ports=ports,
            environment={"SCIONLAB_SITE": self.get_url()},
            detach=True)
        self.container_id = cntr.id
        log.info("Started coordinator %s [%s] (%s).", cntr_name, self.host.name, self.container_id)
        self.bridge.connect_coordinator(self)


    def stop(self):
        """Stop and remove the coordinator's container."""
        if self.container_id is not None:
            dc = self.host.docker_client
            try:
                cntr = dc.containers.get(self.container_id)
            except docker.errors.NotFound:
                self.container_id = None
            else:
                cntr.remove(force=True)
                log.info("Stopped coordinator %s [%s] (%s).", cntr.name, self.host.name, self.container_id)
                self.container_id = None
                self._initialized = False


    def get_peers(self, isd_as: ISD_AS, ixp_id: Optional[int]) -> Optional[Dict]:
        """Get the ASes currently peering with the user AS `isd_as` because of peering policies.

        :params ixp_id: An optional integer identifying an IXP in the coordinator. Filters the
                        result for policies applying to this IXP.
        :return: The dictionary returned by the coordinator's API. Returns `None` if the coordinator
                 is not running.
        """
        try:
            cntr = self.host.docker_client.containers.get(self.container_id)
        except docker.errors.NotFound:
            log.error("Coordinator is not running.")
            return None

        uid, secret = self.api_credentials[isd_as]
        req_params = ("?ixp=%s" % ixp_id) if ixp_id is not None else ""
        cmd = "curl -X GET {base_url}/api/host/{host}/peers{params}" \
              " -u {host}:{secret}".format(
                  base_url=self.get_url(), params=req_params, host=uid, secret=secret)
        response = io.StringIO()
        run_cmd_in_cntr(cntr, const.SCION_USER, cmd, output=response)

        response.seek(0)
        return json.load(response)


    def get_policies(self, isd_as: ISD_AS, ixp_id: Optional[int]) -> Optional[Dict]:
        """Get the peering policies of user AS `isd_as` from the coordinator.

        :params ixp_id: An optional integer identifying an IXP in the coordinator. Filters the
                        result for policies applying to this IXP.
        :return: The dictionary returned by the coordinator's API. Returns `None` if the coordinator
                 is not running.
        """
        try:
            cntr = self.host.docker_client.containers.get(self.container_id)
        except docker.errors.NotFound:
            log.error("Coordinator is not running.")
            return None

        uid, secret = self.api_credentials[isd_as]
        req_params = ("?ixp=%s" % ixp_id) if ixp_id is not None else ""
        cmd = "curl -X GET {base_url}/api/host/{host}/peering_policies{params}" \
              " -u {host}:{secret}".format(
                  base_url=self.get_url(), params=req_params, host=uid, secret=secret)
        response = io.StringIO()
        run_cmd_in_cntr(cntr, const.SCION_USER, cmd, output=response)

        response.seek(0)
        return json.load(response)


    def create_policies(self, isd_as: ISD_AS, policies: str) -> str:
        """Create new peering policies for user AS `isd_as`.

        :params policies: The policies to add in JSON format as expected by the coordinator.
        :return: String containing the HTTP status code.
        """
        try:
            cntr = self.host.docker_client.containers.get(self.container_id)
        except docker.errors.NotFound:
            log.error("Coordinator is not running.")
            return ""

        uid, secret = self.api_credentials[isd_as]
        cmd = "curl -X POST {base_url}/api/host/{host}/peering_policies" \
              " -u {host}:{secret} -d \"{policies}\" -i".format(
                  base_url=self.get_url(), host=uid, secret=secret,
                  policies=policies.replace("'", "\"").replace('"', '\\"'))

        result = io.StringIO()
        run_cmd_in_cntr(cntr, const.SCION_USER, cmd, output=result)
        return result.getvalue().splitlines()[0]


    def delete_policies(self, isd_as: ISD_AS, policies: str) -> str:
        """Delete peering policies for user AS `isd_as`.

        :params policies: The policies to delete in JSON format as expected by the coordinator.
        :return: String containing the HTTP status code.
        """
        try:
            cntr = self.host.docker_client.containers.get(self.container_id)
        except docker.errors.NotFound:
            log.error("Coordinator is not running.")
            return ""

        uid, secret = self.api_credentials[isd_as]
        cmd = "curl -X DELETE {base_url}/api/host/{host}/peering_policies" \
              " -u {host}:{secret} -d \"{policies}\" -i".format(
                  base_url=self.get_url(), host=uid, secret=secret,
                  policies=policies.replace("'", "\"").replace('"', '\\"'))

        result = io.StringIO()
        run_cmd_in_cntr(cntr, const.SCION_USER, cmd, output=result)
        return result.getvalue().splitlines()[0]


    def get_address(self) -> UnderlayAddress:
        """Returns the IP address and TCP port of the coordinator."""
        ip = self.bridge.get_ip_address(self)
        return UnderlayAddress(unwrap(ip), L4Port(const.COORD_PORT))


    def get_url(self) -> str:
        """Returns the URL of the coordinator."""
        return "http://" + self.get_address().format_url()


    def get_config_cmd(self, isd_as: ISD_AS) -> str:
        """Returns the command needed to install the configuration of AS `isd_as`.

        This command will also start SCION if it is not running and a new configuration has been
        found.
        """
        uid, secret = self.api_credentials[isd_as]
        return ("./scionlab-config-user"
                " --host-id {}"
                " --host-secret {}"
                " --url '{}'").format(
                    uid, secret, self.get_url()
                )


def config_ssh_client(topo, workdir: Path):
    """Copy the SSH private key and client configuration to the coordinator."""
    coord = topo.coordinator
    assert coord

    log.info("Copying SSH key to coordinator.")
    cntr = _get_coord_container(coord)
    src_path = workdir.joinpath(const.COORD_KEY_PATH)
    dst_path = Path(const.SCIONLAB_PATH).joinpath("run")

    copy_to_container(cntr, src_path.joinpath(const.COORD_PRIVATE_KEY_FILE), dst_path)

    # Make sure private key is only readable by SCION user
    run_cmd_in_cntr(cntr, const.SCION_USER,
        "chmod 600 %s" % dst_path.joinpath(const.COORD_PRIVATE_KEY_FILE), check=True)

    copy_to_container(cntr, src_path.joinpath(const.SSH_CLIENT_CONFIG), dst_path)

    # Retrieve host keys
    run_cmd_in_cntr(cntr, const.SCION_USER, "umask 077 && mkdir -p ~/.ssh", check=True)
    for isd_as in topo.ases.keys():
        cmd = "ssh-keyscan -H %s >> ~/.ssh/known_hosts" % topo.coordinator.bridge.get_ip_address(isd_as)
        run_cmd_in_cntr(cntr, const.SCION_USER, cmd)


def init_db(topo, workdir: Path):
    """Initialize the coordinator's database with information from `topo`.

    :param topo: Topology database.
    :param workdir: Directory containing the topology data.
    :raises docker.errors.NotFound: The container of the coordinator has not been found.
    """
    coord = topo.coordinator
    assert coord

    log.info("Initializing coordinator database.")
    # Create configuration in working directory (on host)
    output_path = workdir.joinpath(const.COORD_SCRIPT_NAME)
    with open(output_path, 'w') as file:
        _create_config_script(topo, file)

    # Run configuration script in Django
    cntr = _get_coord_container(coord)
    copy_to_container(cntr, output_path, Path(const.SCIONLAB_PATH).joinpath("scripts"))
    cmd = "./manage.py shell < scripts/" + const.COORD_SCRIPT_NAME
    run_cmd_in_cntr(cntr, const.SCION_USER, cmd, check=True)


def _create_config_script(topo, out) -> None:
    """Builds a Python script to be run in context of Django to set up the initial DB contents.

    :param topo: Topology database.
    :param out: Text stream the script is written to.
    """
    coord = topo.coordinator

    # Imports
    out.write("from scionlab.models.core import AS, BorderRouter, Host, Interface, ISD, Link\n")
    out.write("from scionlab.models.user import User\n")
    out.write("from scionlab.models.user_as import AttachmentPoint, UserAS\n")
    out.write("from scionlab.models.ixp import IXP, IXPMember\n")

    # Create users
    for user in topo.coordinator.users.values():
        if user.is_admin:
            out.write("User.objects.create_superuser('%s', '%s')\n" % (user.email, user.password))
        else:
            out.write("User.objects.create_user('%s', '%s')\n" % (user.email, user.password))

    # Create ISDs
    isds = []
    for isd_as in topo.ases.keys():
        isd = isd_as[0]
        if isd not in isds:
            out.write("ISD.objects.create(isd_id=%d, label='%s')\n" % (isd, isd_as.isd_str()))
            isds.append(isd)

    # Create infrastructure ASes
    for isd_as, asys in topo.ases.items():
        if not asys.is_user_as():
            out.write("isd = ISD.objects.get(isd_id=%d)\n" % isd_as[0])
            bind_ip = coord.bridge.get_bind_ip(isd_as, asys)
            bind_ip_str = "'%s'" % bind_ip if bind_ip else "None"
            out.write(
                "asys = AS.objects.create_with_default_services("\
                "isd, as_id='%s', public_ip='%s', bind_ip=%s, is_core=%s)\n" %
                    (isd_as.as_str(), coord.bridge.get_ip_address(isd_as), bind_ip_str, asys.is_core))
            out.write("host = asys.hosts.first()\n")
            if asys.is_attachment_point:
                # Attachment points have to support managemnet via SSH
                out.write("host.managed = True\n")
                out.write("host.ssh_host = '%s'\n" % coord.bridge.get_ip_address(isd_as))
                out.write("host.save()\n")
            for br in asys.border_routers:
                out.write("br = BorderRouter.objects.create(host)\n")
                for ifid, link in br.links.items():
                    _gen_create_interfaces(isd_as, asys, link, ifid, out)

    # Create infrastructure links
    for link in topo.links:
        if link.ep_a.is_zero() or link.ep_b.is_zero():
            continue # dummy links
        if topo.ases[link.ep_a].is_user_as() or topo.ases[link.ep_b].is_user_as():
            continue # links to or between user ASes
        _gen_create_link(link, out)

    # Create attachment points
    for isd_as, asys in topo.ases.items():
        if asys.is_attachment_point:
            _gen_get_as("asys", isd_as, out)
            out.write("AttachmentPoint.objects.create(AS=asys)\n")

    # Create user ASes
    for isd_as, asys in topo.ases.items():
        if asys.is_user_as():
            ap_ifid, ap_link = _get_ap_link(topo, asys)
            if ap_link is None:
                log.warning("User AS {} is not attached to infrastructure.".format(isd_as))
                continue

            # Create the user AS. This also creates the BR connecting to the AP.
            local_addr, remote_addr = ap_link.get_underlay_addresses(isd_as)
            bind_ip_str, bind_port_str = _format_underlay_addr(
                ap_link.bridge.get_br_bind_address(isd_as, asys, ap_ifid))
            ap = ap_link.get_other_endpoint(isd_as)

            _gen_get_as("asys", ap, out)
            out.write("user = User.objects.get(email='%s')\n" % topo.coordinator.users[asys.owner].email)
            out.write("ap = AttachmentPoint.objects.get(AS=asys)\n")

            out.write(
                ("asys = UserAS.objects.create(user, ap, {local_port}, UserAS.SRC, as_id='{isd_as}',"
                 " public_ip='{local_ip}', bind_ip={bind_ip}, bind_port={bind_port},"
                 " public_ip_ap='{remote_ip}', public_port_ap='{remote_port}')\n").format(
                     isd_as=isd_as.as_str(),
                     local_ip=local_addr.ip,
                     local_port=local_addr.port,
                     bind_ip = bind_ip_str,
                     bind_port = bind_port_str,
                     remote_ip=remote_addr.ip,
                     remote_port=remote_addr.port
                 ))

            # Get the BR created by UserAS.objects.create().
            out.write("br = BorderRouter.objects.get(host__AS=asys)\n")

            # Change the interface ID of the AP interface to match our topology.
            out.write("Interface.objects.filter(AS=asys).update(interface_id=%d)\n" % ap_ifid)

            # Create the remaining interfaces of the BR connecting to the AP.
            ap_br = asys.get_border_router(ap_ifid)
            for ifid, link in ap_br.links.items():
                if ifid != ap_ifid:
                    _gen_create_interfaces(isd_as, asys, link, ifid, out)

            # Create the remaining BRs and their interfaces.
            if len(asys.border_routers) > 1:
                out.write("host = Host.objects.get(AS=asys)\n")
                for br in asys.border_routers:
                    if br is not ap_br:
                        out.write("br = BorderRouter.objects.create(host)\n")
                        for ifid, link in br.links.items():
                            _gen_create_interfaces(isd_as, asys, link, ifid, out)

    # Create links between user ASes
    for link in topo.links:
        if link.ep_a.is_zero() or link.ep_b.is_zero():
            continue # dummy links
        if topo.ases[link.ep_a].is_user_as() and topo.ases[link.ep_b].is_user_as():
            _gen_create_link(link, out)

    # Create IXPs
    for name, ixp in topo.ixps.items():
        net = str(ixp.bridge.ip_network)
        out.write("IXP.objects.create(label='%s', ip_network='%s')\n" % (name, net))

    # Set IXP memberships
    for ixp_name, ixp in topo.ixps.items():
        for isd_as, asys in ixp.ases.items():
            out.write("ixp = IXP.objects.get(label='%s')\n" % ixp_name)
            out.write("asys = UserAS.objects.get(isd__isd_id=%d, as_id_int=%d)\n" %
                (isd_as[0], isd_as[1]))
            out.write("IXPMember.objects.create(ixp=ixp, host=asys.hosts.first(), public_ip='%s')\n" %
                str(ixp.bridge.get_ip_address(isd_as)))


def _gen_create_interfaces(isd_as, asys, link, ifid, out) -> None:
    """Generate code creating a new interface object.

    :param out: Stream the generated code is written to.
    """
    local, _ = link.get_underlay_addresses(isd_as)
    bind_addr = link.bridge.get_br_bind_address(isd_as, asys, ifid)
    bind_ip_str, bind_port_str = _format_underlay_addr(bind_addr)
    out.write(
        "Interface.objects.create("
        "br, interface_id=%s, public_ip='%s', public_port=%d, bind_ip=%s, bind_port=%s)\n" %
            (ifid, local.ip, local.port, bind_ip_str, bind_port_str))


def _gen_get_as(dst: str, isd_as: ISD_AS, out) -> None:
    """Generate code assigning the AS identified by `isd_as` to a variable called `dst`.

    :param out: Stream the generated code is written to.
    """
    out.write("%s = AS.objects.get(isd__isd_id=%d, as_id_int=%d)\n" %
        (dst, isd_as[0], isd_as[1]))


def _gen_get_iface(dst: str, isd_as: ISD_AS, ifid: IfId, out) -> None:
    """Generate code assigning interface `ifid` of AS `isd_as` to the Python variable named `dst`.

    :param out: Stream the generated code is written to.
    """
    _gen_get_as("asys", isd_as, out)
    out.write("%s = Interface.objects.get(AS=asys, interface_id=%d)\n" % (dst, ifid))


def _gen_create_link(link: Link, out) -> None:
    """Generate code creating a link between two already existing BR interfaces.

    :param out: Stream the generated code is written to.
    """
    _gen_get_iface('a', link.ep_a, link.ep_a.ifid, out)
    _gen_get_iface('b', link.ep_b, link.ep_b.ifid, out)
    if link.type != LinkType.PARENT:
        out.write("Link.objects.create(%s, a, b)\n" % _get_link_type_constant(link.type))
    else:
        # The coordinator knows only 'child' ('PROVIDER') links, no 'parent' links.
        out.write("Link.objects.create(%s, b, a)\n" % _get_link_type_constant(LinkType.CHILD))


def _get_link_type_constant(link_type: str) -> str:
    """Translate the link types used in topology definitions to the ones used by the coordinator.

    LinkType.PARENT has no equivalent constant.

    :returns: Link type as type symbolic constant.
    """
    link_type = link_type.lower()
    if link_type == LinkType.CHILD:
        return 'Link.PROVIDER'
    elif link_type == LinkType.CORE:
        return 'Link.CORE'
    elif link_type == LinkType.PEER:
        return 'Link.PEER'
    else:
        raise KeyError()


def _get_ap_link(topo, user_as: AS):
    """Get the link connecting a user AS to its attachment point.

    Every user AS should have exactly one link connecting it to an AP.

    :return: Tuple of the interface ID on the user AS's side and the link to the AP.
             Returns `(None, None)` if there is no link to an attachment point.
    """
    for ifid, link in user_as.links():
        if link.ep_a.is_zero() or link.ep_b.is_zero():
            continue # dummy links
        if topo.ases[link.ep_a].is_attachment_point or topo.ases[link.ep_b].is_attachment_point:
            return (ifid, link)
    return (None, None)


def _format_underlay_addr(addr: Optional[UnderlayAddress]) -> Tuple[str, str]:
    """Returns an underlay address as a pair of IP address and port number as strings.

    The IP address is enclosed in single quotes. If `addr` is `None`, returns `(None, None)`.
    """
    if addr is not None:
        return "'%s'" % addr.ip, str(addr.port)
    else:
        return ("None", "None")


def fetch_api_secrets(topo):
    """Retrieve coordinator API credentials for all ASes in the topology."""
    coord = topo.coordinator
    assert coord

    log.info("Fetching API secrets from coordinator.")
    cntr = _get_coord_container(coord)
    secrets = io.StringIO()
    cmd = "./manage.py shell < scripts/print_api_secrets.py"
    run_cmd_in_cntr(cntr, const.SCION_USER, cmd, output=secrets, check=True)
    coord.api_credentials = _parse_api_secrets(secrets.getvalue())


def _parse_api_secrets(input: str) -> Dict[ISD_AS, ApiCredentials]:
    """Parse the output of the 'print_api_secrets.py' script running in context of the coordinator."""
    output = {}

    for line in input.splitlines():
        isd_as_str, uid, secret = line.split()
        output[ISD_AS(isd_as_str)] = ApiCredentials(uid, secret)

    return output


def _get_coord_container(coord: Coordinator):
    """Returns the coordinator's container."""
    dc = coord.host.docker_client
    try:
        return dc.containers.get(coord.container_id)
    except docker.errors.NotFound:
        log.error("Coordinator is not running.")
        raise
