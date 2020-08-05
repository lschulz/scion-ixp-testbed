"""Class representing a SCIONLab coordinator and types and functions supporting its configuration.
"""
from abc import ABC, abstractmethod
import io
import json
import logging
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, NamedTuple, Optional, Tuple

import docker
from lib.types import LinkType

from ixp_testbed import constants as const
from ixp_testbed.address import ISD_AS, IfId, IpAddress, L4Port, UnderlayAddress
import ixp_testbed.errors as errors
from ixp_testbed.host import Host
from ixp_testbed.network.bridge import Bridge
from ixp_testbed.scion import AS, Link
from ixp_testbed.util.cpu_affinity import CpuSet
from ixp_testbed.util.docker import copy_to_container, run_cmd_in_cntr
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)

_PROD_DJANGO_COORD_URL = "http://django:8000"
"""URL of the Gunicorn webserver in the internal network of the production coordinator.
In the coordinator's containers, Docker resolves the name 'django' to the right container's IP
"""


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


class _CoordBase(ABC):
    """Base class for coordinator docker container managers."""
    @abstractmethod
    def get_django_container(self, docker_client: docker.DockerClient):
        raise NotImplementedError()

    @abstractmethod
    def get_web_container(self, docker_client: docker.DockerClient):
        raise NotImplementedError()

    @abstractmethod
    def get_ssh_container(self, docker_client: docker.DockerClient):
        raise NotImplementedError()

    def _get_container(self, docker_client: docker.DockerClient, cntr_id: Optional[str]):
        if cntr_id is None:
            raise errors.NotFound()
        else:
            try:
                return docker_client.containers.get(cntr_id)
            except docker.errors.NotFound:
                raise errors.NotFound()

    @abstractmethod
    def print_status(self, host: Host, out) -> None:
        """Print the status if the coordinator's containers.

        :param host: Host the coordinator is running on.
        :param out: Text stream to print to.
        """
        raise NotImplementedError()

    @abstractmethod
    def reserve_ip_addresses(self, bridge: Bridge, ip_gen: Optional[Iterator[IpAddress]] = None):
        """Reserve IP addresses for the coordinator.

        :param ip_gen: Optional sequence the IP addresses are taken from.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_http_interface(self, bridge: Bridge) -> UnderlayAddress:
        """Returns the IP address and TCP port of the coordinator's HTTP interface.

        :param bridge: The network in which an IP address has been reserved for the coordinator with
                       reserve_ip_addresses().
        """
        return NotImplementedError()

    @abstractmethod
    def wait_for_db_migrations(self, docker_client: docker.DockerClient, timeout: int) -> None:
        """Block until 'manage.py migrate' has completed.

        :param timeout: Maximum wait time in seconds.
        :param docker_client: Docker client connected to the coordinator's host.
        """
        return NotImplementedError()


class _DebugCoord(_CoordBase):
    """Manages the debug coordinator's container."""
    _COORD_DEBUG_SERVER = "coordinator"
    IDENTITY_FILE_PATH = "/scionlab/run/coord_id_rsa"
    """Path to the private key for authentication at managed ASes."""

    def __init__(self, coord_name: str):
        """
        :param coord_name: Name of the coordinator's container.
        """
        self._cntr_id: Optional[str] = None
        self._cntr_name = coord_name

    def get_django_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._cntr_id)

    def get_web_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._cntr_id)

    def get_ssh_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._cntr_id)

    def print_status(self, host: Host, out) -> None:
        status = "no container"
        if self._cntr_id:
            dc = host.docker_client
            try:
                cntr = dc.containers.get(self._cntr_id)
                status = cntr.status
            except docker.errors.NotFound:
                log.warning("Container container (%s) not found.", self._cntr_id)
        out.write("### Coordinator: {} ({})\n".format(status, self._cntr_name))

    def reserve_ip_addresses(self, bridge: Bridge, ip_gen: Optional[Iterator[IpAddress]] = None):
        bridge.assign_ip_address(self._COORD_DEBUG_SERVER,
            next(ip_gen) if ip_gen is not None else None)

    def get_http_interface(self, bridge: Bridge) -> UnderlayAddress:
        return UnderlayAddress(
            unwrap(bridge.get_ip_address(self._COORD_DEBUG_SERVER)),
            L4Port(const.COORD_PORT))

    def wait_for_db_migrations(self, docker_client: docker.DockerClient, timeout: int):
        # 'manage.py migrate' is executed during image creation
        return

    def start(self, *,
        host: Host, bridge: Bridge, internal_url: str,
        publish_at: Optional[UnderlayAddress], cpu_affinity: CpuSet, **args) -> None:
        dc = host.docker_client

        # Check wheather the coordinator is already running
        if self._cntr_id:
            try:
                cntr = dc.containers.get(self._cntr_id)
            except docker.errors.NotFound:
                self._cntr_id = None
            else:
                if cntr.status == 'running':
                    return # coordinator is already running
                else:
                    # Remove old container
                    cntr.stop()
                    cntr.remove()

        # Expose coordinator on host interface
        ports = {}
        if publish_at is not None:
            external_ip, external_port = publish_at
            ports['%d/tcp' % const.COORD_PORT] = (str(external_ip), int(external_port))
            log.info("Exposing coordinator at http://%s", publish_at.format_url())

        # Create and run the container
        kwargs = {}
        if not cpu_affinity.is_unrestricted():
            kwargs['cpuset_cpus'] = str(cpu_affinity)
        cntr = dc.containers.run(const.COORD_IMG_NAME,
            name=self._cntr_name,
            ports=ports,
            environment={"SCIONLAB_SITE": internal_url},
            detach=True,
            **kwargs)
        self._cntr_id = cntr.id
        log.info("Started coordinator %s [%s] (%s).", self._cntr_name, host.name, self._cntr_id)
        ip = unwrap(bridge.get_ip_address(self._COORD_DEBUG_SERVER))
        bridge.connect_container(cntr, ip, host)

    def stop(self, host: Host):
        """Stop and remove the coordinator's container."""
        if self._cntr_id is not None:
            dc = host.docker_client
            try:
                cntr = dc.containers.get(self._cntr_id)
            except docker.errors.NotFound:
                self._cntr_id = None
            else:
                cntr.remove(force=True)
                log.info("Stopped coordinator %s [%s] (%s).", cntr.name, host.name, self._cntr_id)
                self._cntr_id = None


class _ProductionCoord(_CoordBase):
    """Manages the production coordinator's containers through docker-compose."""
    _COORD_CADDY = "coordinator_caddy"
    _COORD_HUEY = "coordinator_huey"
    IDENTITY_FILE_PATH = "/scionlab/run/coord_id_rsa"
    """Path to the private key for authentication at managed ASes."""

    def __init__(self, coord_name: str, compose_path: Path):
        """
        :param coord_name: Project name passed to docker-compose. Used as prefix for image,
                           container, network, and volume names.
        :param compose_path: Path to the coordinator's docker-compose file.
        """
        self._project_name = coord_name
        self._compose_path = compose_path
        self._django_cntr_id: Optional[str] = None
        self._caddy_cntr_id: Optional[str] = None
        self._huey_cntr_id: Optional[str] = None

    def _compose_cmd(self, subcommand: Iterable[str]) -> List[str]:
        """"Build a docker-compose command line."""
        cmd = ["docker-compose", "-f", str(self._compose_path), "-p", self._project_name]
        cmd.extend(subcommand)
        return cmd

    def get_django_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._django_cntr_id)

    def get_web_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._caddy_cntr_id)

    def get_ssh_container(self, docker_client: docker.DockerClient):
        return self._get_container(docker_client, self._huey_cntr_id)

    def print_status(self, host: Host, out) -> None:
        result = host.run_cmd(self._compose_cmd(["ps"]), capture_output=True)
        out.write("### Coordinator:\n")
        out.write(result.output)

    def reserve_ip_addresses(self, bridge: Bridge, ip_gen: Optional[Iterator[IpAddress]] = None):
        bridge.assign_ip_address(self._COORD_CADDY, next(ip_gen) if ip_gen is not None else None)
        bridge.assign_ip_address(self._COORD_HUEY, next(ip_gen) if ip_gen is not None else None)

    def get_http_interface(self, bridge: Bridge) -> UnderlayAddress:
        return UnderlayAddress(
            unwrap(bridge.get_ip_address(self._COORD_CADDY)),
            L4Port(const.COORD_PORT))

    def wait_for_db_migrations(self, docker_client: docker.DockerClient, timeout: int) -> None:
        cmd = "appdeps.py --wait-secs {} --file-wait db_initialized".format(timeout)
        run_cmd_in_cntr(
            self.get_django_container(docker_client), const.SCIONLAB_USER_PRODUCTION, cmd)

    def start(self, *,
        host: Host, bridge: Bridge, internal_url: str,
        publish_at: Optional[UnderlayAddress], cpu_affinity: CpuSet, **args) -> None:
        dc = host.docker_client

        # Check wheather the coordinator is already running
        restart_existing = False
        if self._django_cntr_id:
            result = host.run_cmd(self._compose_cmd(["ps"]), check=True, capture_output=True)
            lines = result.output.splitlines()
            if len(lines) < 3:
                # coordinator is down
                restart_existing = False
            else:
                for line in lines:
                    if line.startswith(self._project_name) and not "Up" in line:
                        # some containers are not running
                        restart_existing = True
                        break
                else:
                    return # coordinator is already running

        # Invoke docker-compose
        if restart_existing:
            result = host.run_cmd(self._compose_cmd(["restart"]), check=True, capture_output=True)
            log.info("Restarting coordinator containers:\n" + result.output)

        else:
            env = {
                "SCIONLAB_SITE": internal_url,
                "COORD_CPUSET": str(cpu_affinity),
                "COORD_ADDR": str(publish_at) if publish_at is not None else ""
            }
            if publish_at is not None:
                log.info("Exposing coordinator at http://%s", publish_at.format_url())

            result = host.run_cmd(self._compose_cmd(["up", "--detach"]), env=env, check=True,
                capture_output=True)
            log.info("Starting coordinator:\n%s", result.output)

        # Get the django and the caddy container
        django_cntr = dc.containers.get(self._project_name + "_django_1")
        self._django_cntr_id= django_cntr.id
        caddy_cntr = dc.containers.get(self._project_name + "_caddy_1")
        self._caddy_cntr_id = caddy_cntr.id
        huey_cntr = dc.containers.get(self._project_name + "_huey_1")
        self._huey_cntr_id = huey_cntr.id

        # Connect caddy to the coordinator network to publish the web interface
        bridge.connect_container(caddy_cntr, unwrap(bridge.get_ip_address(self._COORD_CADDY)), host)
        # Connect huey to the coordinator network to enable AS configuration over SSH
        bridge.connect_container(huey_cntr, unwrap(bridge.get_ip_address(self._COORD_HUEY)), host)

    def stop(self, host):
        """Stop and remove the coordinator's containers, internal network, and volumes."""
        result = host.run_cmd(self._compose_cmd(["down", "-v"]), check=True, capture_output=True)
        log.info("Stopping coordinator:\n%s", result.output)
        self._django_cntr_id = None
        self._caddy_cntr_id = None
        self._huey_cntr_id = None


class Coordinator:
    """Contains information on an instance of the SCIONLab coordinator.

    :ivar host: Host running the coordinator.
    :ivar cpu_affinity: The CPUs on `host` the coordinator is allowed to run on.
    :ivar bridge: Network for communication with ASes.
    :ivar exposed_at: Host address to expose the coordinator on.
    :ivar container_id: ID of the Docker container running the coordinator.
    :ivar users: Mapping from user name to user data. The user name is only used by this script.
                 The coordinator identifies users by their email address.
    :ivar api_credentials: Coordinator API credentials for all ASes.
    :ivar ssh_management: Controls whether the coordinator has SSH access to all ASes, instead of
                          just attachment points.
    :ivar _containers: Container(s) hosting the coordinator and its support services.
    :ivar _initialized: Flag indicating whether the coordinator has been initialized.
    """
    def __init__(self, coord_name: str, host: Host, bridge: Bridge, cpu_affinity: CpuSet = CpuSet(),
        ssh_management: bool = False, debug: bool = True, compose_path: Optional[Path] = None):
        """
        :param coord_name: Name of the coordinator instance. Used as a name prefix for images,
                           containers, networks, and volumes created for the coordinator.
        :param host: Host running the coordinator.
        :param cpu_affinity: The CPUs on `host` the coordinator is allowed to run on.
        :param ssh_management: Controls whether the coordinator has SSH access to all ASes, instead
                               of just attachment points. Automatic deployment of AS configurations
                               is only available for APs and currently only works if `debug=false`.
        :param debug: Whether to run the coordinator in debug mode. If the coordinator is run in
                      debug mode, it uses an SQLite database and runs in a single container.
                      If debug mode is disabled, multiple container are started by invoking
                      docker-compose on `host`. In this mode a PosgreSQL DB stores the coordinator's
                      data. Running docker-compose requires the coordinator's source to be present
                      on `host`. Use `compose_path` to specify the location of the directory
                      containing the compose file on `host`.
        :param compose_path: Path to the coordinator's docker-compose file on `host`. Only necessary
                             when `debug` is false.
        """
        self.host = host
        self.cpu_affinity = cpu_affinity
        self.bridge = bridge
        self.exposed_at: Optional[UnderlayAddress] = None
        self.users: Dict[str, User] = {}
        self.api_credentials: Dict[ISD_AS, ApiCredentials]
        self.ssh_management = ssh_management
        if debug:
            self._containers = _DebugCoord(coord_name)
        else:
            self._containers =_ProductionCoord(coord_name, unwrap(compose_path))
        self._initialized = False

    @property
    def debug(self):
        """True, if the coordinator is running in debug mode."""
        return isinstance(self._containers, _DebugCoord)

    def init(self, topo, workdir: Path):
        """Initialize the coordinators database.

        Checks it the coordinator needs initialization. If it does, the coordinators's database is
        populated with the topology definition and the data needed for automatic AS deployment is
        exchanged.
        """
        assert topo.coordinator is self
        if not self._initialized:
            if self.ssh_management:
                config_ssh_client(topo, workdir, self.debug)
            self._containers.wait_for_db_migrations(self.host.docker_client,
                const.COORD_DB_MIGRATION_TIMEOUT)
            init_db(topo, workdir, self.debug)
            fetch_api_secrets(topo, self.debug)
            self._initialized = True

    def get_identity_file_path(self) -> str:
        """"Returns the path the coordinator's private key within its container."""
        return self._containers.IDENTITY_FILE_PATH

    def get_django_container(self):
        """Get the container the coordinator web app is running in.

        :raises errors.NotFound The container could not be retrieved, because the coordinator is not
        running or the container has exited unexpectedly.
        """
        return self._containers.get_django_container(self.host.docker_client)

    def get_web_container(self):
        """Get the container the public web server is running in.

        :raises errors.NotFound The container could not be retrieved, because the coordinator is not
        running or the container has exited unexpectedly.
        """
        return self._containers.get_web_container(self.host.docker_client)

    def get_ssh_container(self):
        """Get the container providing AS configuration over SSH.

        :raises errors.NotFound The container could not be retrieved, because the coordinator is not
        running or the container has exited unexpectedly.
        """
        return self._containers.get_ssh_container(self.host.docker_client)

    def get_br_prom_ports(self, isd_as: ISD_AS) -> List[L4Port]:
        """Get the Prometheus endpoint ports of all border routers in the given AS."""
        ports = io.StringIO()
        cntr = self.get_django_container()
        user = const.SCIONLAB_USER_DEBUG if self.debug else const.SCIONLAB_USER_PRODUCTION
        cmd = "./manage.py runscript print_prom_ports --script-args %s" % isd_as.as_str()
        run_cmd_in_cntr(cntr, user, cmd, output=ports, check=True)
        return [L4Port(int(port)) for port in ports.getvalue().split()]

    def print_status(self, out) -> None:
        """Print the status of the coordinator's containers to `out`."""
        self._containers.print_status(self.host, out)

    def reserve_ip_addresses(self, ip_gen: Optional[Iterator[IpAddress]] = None):
        """Reserve IP addresses for the coordinator's containers.

        :param ip_gen: Optional sequence the IP addresses to reserve are taken from.
        """
        self._containers.reserve_ip_addresses(self.bridge, ip_gen)

    def start(self) -> None:
        """Start the coordinator's container(s)."""
        self._containers.start(host=self.host, bridge=self.bridge, internal_url=self.get_url(),
            publish_at=self.exposed_at, cpu_affinity=self.cpu_affinity)

    def stop(self):
        """Stop and remove the coordinator's container."""
        self._containers.stop(host=self.host)
        self._initialized = False

    def get_peers(self, isd_as: ISD_AS, ixp_id: Optional[int]) -> Optional[Dict]:
        """Get the ASes currently peering with the user AS `isd_as` because of peering policies.

        :params ixp_id: An optional integer identifying an IXP in the coordinator. Filters the
                        result for policies applying to this IXP.
        :return: The dictionary returned by the coordinator's API. Returns `None` if the coordinator
                 is not running.
        """
        try:
            # Production configuration: Caddy container does not have curl, so run directly in the
            # Django container.
            cntr = self.get_web_container() if self.debug else self.get_django_container()
        except errors.NotFound:
            log.error("Coordinator is not running.")
            return None

        uid, secret = self.api_credentials[isd_as]
        req_params = ("?ixp=%s" % ixp_id) if ixp_id is not None else ""
        cmd = "curl -X GET {base_url}/api/peering/host/{host}/peers{params}" \
              " -u {host}:{secret}".format(
                  base_url=self.get_url() if self.debug else _PROD_DJANGO_COORD_URL,
                  params=req_params, host=uid, secret=secret)
        user = const.SCIONLAB_USER_DEBUG if self.debug else const.SCIONLAB_USER_PRODUCTION
        response = io.StringIO()
        run_cmd_in_cntr(cntr, user, cmd, output=response)

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
            # Production configuration: Caddy container does not have curl, so run directly in the
            # Django container.
            cntr = self.get_web_container() if self.debug else self.get_django_container()
        except errors.NotFound:
            log.error("Coordinator is not running.")
            return None

        uid, secret = self.api_credentials[isd_as]
        req_params = ("?ixp=%s" % ixp_id) if ixp_id is not None else ""
        cmd = "curl -X GET {base_url}/api/peering/host/{host}/policies{params}" \
              " -u {host}:{secret}".format(
                  base_url=self.get_url() if self.debug else _PROD_DJANGO_COORD_URL,
                  params=req_params, host=uid, secret=secret)
        user = const.SCIONLAB_USER_DEBUG if self.debug else const.SCIONLAB_USER_PRODUCTION
        response = io.StringIO()
        run_cmd_in_cntr(cntr, user, cmd, output=response)

        response.seek(0)
        return json.load(response)


    def create_policies(self, isd_as: ISD_AS, policies: str) -> str:
        """Create new peering policies for user AS `isd_as`.

        :params policies: The policies to add in JSON format as expected by the coordinator.
        :return: String containing the HTTP status code.
        """
        try:
            # Production configuration: Caddy container does not have curl, so run directly in the
            # Django container.
            cntr = self.get_web_container() if self.debug else self.get_django_container()
        except errors.NotFound:
            log.error("Coordinator is not running.")
            return ""

        uid, secret = self.api_credentials[isd_as]
        cmd = "curl -X POST {base_url}/api/peering/host/{host}/policies" \
              " -u {host}:{secret} -d \"{policies}\" -i".format(
                  base_url=self.get_url() if self.debug else _PROD_DJANGO_COORD_URL,
                  host=uid, secret=secret,
                  policies=policies.replace("'", "\"").replace('"', '\\"'))

        user = const.SCIONLAB_USER_DEBUG if self.debug else const.SCIONLAB_USER_PRODUCTION
        result = io.StringIO()
        run_cmd_in_cntr(cntr, user, cmd, output=result)
        return result.getvalue().splitlines()[0]


    def delete_policies(self, isd_as: ISD_AS, policies: str) -> str:
        """Delete peering policies for user AS `isd_as`.

        :params policies: The policies to delete in JSON format as expected by the coordinator.
        :return: String containing the HTTP status code.
        """
        try:
            # Production configuration: Caddy container does not have curl, so run directly in the
            # Django container.
            cntr = self.get_web_container() if self.debug else self.get_django_container()
        except errors.NotFound:
            log.error("Coordinator is not running.")
            return ""

        uid, secret = self.api_credentials[isd_as]
        cmd = "curl -X DELETE {base_url}/api/peering/host/{host}/policies" \
              " -u {host}:{secret} -d \"{policies}\" -i".format(
                  base_url=self.get_url() if self.debug else _PROD_DJANGO_COORD_URL,
                  host=uid, secret=secret,
                  policies=policies.replace("'", "\"").replace('"', '\\"'))

        user = const.SCIONLAB_USER_DEBUG if self.debug else const.SCIONLAB_USER_PRODUCTION
        result = io.StringIO()
        run_cmd_in_cntr(cntr, user, cmd, output=result)
        return result.getvalue().splitlines()[0]


    def get_address(self) -> UnderlayAddress:
        """Returns the IP address and TCP port of the coordinator's HTTP interface."""
        return self._containers.get_http_interface(self.bridge)


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


def config_ssh_client(topo, workdir: Path, debug: bool):
    """Copy the SSH private key and client configuration to the coordinator."""
    coord = topo.coordinator
    assert coord

    log.info("Copying SSH key to coordinator.")
    try:
        cntr = coord.get_ssh_container()
    except errors.NotFound:
        log.error("Coordinator is not running.")
        raise

    src_path = workdir.joinpath(const.COORD_KEY_PATH)
    if debug:
        dst_path = Path(const.SCIONLAB_PATH_DEBUG).joinpath("run")
        user = const.SCIONLAB_USER_DEBUG
    else:
        dst_path = Path(const.SCIONLAB_PATH_PRODUCTION).joinpath("run")
        user = const.SCIONLAB_USER_PRODUCTION

    copy_to_container(cntr, src_path.joinpath(const.COORD_PRIVATE_KEY_FILE), dst_path)

    # Make sure private key is only readable by the current user (otherwise ssh does not accept it)
    run_cmd_in_cntr(cntr, user,
        "chmod 600 %s" % dst_path.joinpath(const.COORD_PRIVATE_KEY_FILE), check=True)

    copy_to_container(cntr, src_path.joinpath(const.SSH_CLIENT_CONFIG), dst_path)

    # Retrieve host keys
    run_cmd_in_cntr(cntr, user, "umask 077 && mkdir -p ~/.ssh", check=True)
    for isd_as in topo.ases.keys():
        cmd = "ssh-keyscan -H %s >> ~/.ssh/known_hosts" % (
            topo.coordinator.bridge.get_ip_address(isd_as))
        run_cmd_in_cntr(cntr, user, cmd)


def init_db(topo, workdir: Path, debug):
    """Initialize the coordinator's database with information from `topo`.

    :param topo: Topology database.
    :param workdir: Directory containing the topology data.
    :raises errors.NotFound: The container of the coordinator has not been found.
    """
    coord = topo.coordinator
    assert coord

    log.info("Initializing coordinator database.")
    # Create configuration in working directory (on host)
    output_path = workdir.joinpath(const.COORD_SCRIPT_NAME)
    with open(output_path, 'w') as file:
        _create_config_script(topo, file)

    # Run configuration script in Django
    try:
        cntr = coord.get_django_container()
    except errors.NotFound:
        log.error("Coordinator is not running.")
        raise

    if debug:
        path = Path(const.SCIONLAB_PATH_DEBUG)
        user = const.SCIONLAB_USER_DEBUG
    else:
        path = Path(const.SCIONLAB_PATH_PRODUCTION)
        user = const.SCIONLAB_USER_PRODUCTION
    copy_to_container(cntr, output_path, path.joinpath("scripts"))
    cmd = "./manage.py shell < scripts/" + const.COORD_SCRIPT_NAME
    run_cmd_in_cntr(cntr, user, cmd, check=True)


def _create_config_script(topo, out) -> None:
    """Builds a Python script to be run in context of Django to set up the initial DB contents.

    :param topo: Topology database.
    :param out: Text stream the script is written to.
    """
    coord = topo.coordinator

    # Imports
    out.write("from scionlab.models.core import AS, BorderRouter, Host, Interface, ISD, Link\n")
    out.write("from scionlab.models.user import User\n")
    out.write("from scionlab.models.user_as import AttachmentConf, AttachmentPoint, UserAS\n")
    out.write("from scionlab_ixp.models import IXP, IXPMember\n")

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
            if asys.is_attachment_point or coord.ssh_management:
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
        if link.is_dummy():
            continue
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
            # Create the user AS without any border routers and links.
            out.write("user = User.objects.get(email='%s')\n" % topo.coordinator.users[asys.owner].email)
            out.write("isd = ISD.objects.get(isd_id=%s)\n" % isd_as.isd_str())
            out.write("asys = UserAS.objects.create(user, UserAS.SRC, isd, '{as_id}')\n".format(
                as_id=isd_as.as_str()
            ))

            # Create links to the attachment points. All attachment point links use the first BR of
            # the user AS. Border routers on the AP's side are created and destroyed dynamically by
            # the coordinator to balance the number of links per router.
            attachmentLinks = _get_ap_links(topo, asys)
            if len(attachmentLinks) == 0:
                log.warning("User AS {} is not attached to infrastructure.".format(isd_as))

            out.write("attachments = []\n")
            for attach in attachmentLinks:
                out.write("ap = AttachmentPoint.objects.get(AS__as_id='%s')\n" % attach.ap_id.as_str())
                user_bind_ip, user_bind_port = _format_underlay_addr(attach.user_bind_addr)
                out.write(
                    "attachments.append(AttachmentConf(ap, '{public_ip}', {public_port},"
                    " {bind_ip}, {bind_port}, use_vpn=False))\n".format(
                        public_ip=attach.user_public_addr.ip,
                        public_port=attach.user_public_addr.port,
                        bind_ip=user_bind_ip,
                        bind_port=user_bind_port
                    ))
            out.write("asys.update_attachments(attachments)\n")

            # Update the interfaces created by the coordinator.
            for i, attach in enumerate(attachmentLinks):
                out.write("link = attachments[%d].link\n" % i)

                # Set the correct IP address and port on the AP side of the link.
                ap_bind_ip, ap_bind_port = _format_underlay_addr(attach.ap_bind_addr)
                out.write("link.interfaceA.update(public_ip='{public_ip}', public_port={public_port},"
                    " bind_ip={bind_ip}, bind_port={bind_port})\n".format(
                        public_ip=attach.ap_public_addr.ip,
                        public_port=attach.ap_public_addr.port,
                        bind_ip=ap_bind_ip,
                        bind_port=ap_bind_port
                    ))

                # Change the interface ID at the user AS to match our topology.
                out.write("link.interfaceB.interface_id=%d\n" % attach.user_ifid)
                out.write("link.interfaceB.save()\n")

            # Create the remaining interfaces of the BR connecting to the APs.
            ap_br = None   # BR in the user AS connecting to the AP
            got_br = False # Whether the line getting the BR conneting to the APs has been generated
            if len(attachmentLinks) > 0:
                ap_br = asys.get_border_router(attachmentLinks[0].user_ifid)
                for ifid, link in ap_br.links.items():
                    if not link.is_dummy() and ifid != attachmentLinks[0].user_ifid:
                        if not got_br:
                            out.write("br = BorderRouter.objects.get(AS=asys)\n")
                            got_br = True
                        _gen_create_interfaces(isd_as, asys, link, ifid, out)

            # Create the remaining BRs and their interfaces.
            if len(asys.border_routers) > 1:
                out.write("host = Host.objects.get(AS=asys)\n")
                for br in asys.border_routers:
                    if br is not ap_br:
                        out.write("br = BorderRouter.objects.create(host)\n")
                        for ifid, link in br.links.items():
                            if not link.is_dummy():
                                _gen_create_interfaces(isd_as, asys, link, ifid, out)

            if topo.coordinator.ssh_management:
                out.write("host = Host.objects.get(AS=asys)\n")
                out.write("host.managed = True\n")
                out.write("host.ssh_host = '%s'\n" % coord.bridge.get_ip_address(isd_as))
                out.write("host.save()\n")

    # Create links between user ASes
    for link in topo.links:
        if link.is_dummy():
            continue
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
    _gen_get_iface('a', link.ep_a, unwrap(link.ep_a.ifid), out)
    _gen_get_iface('b', link.ep_b, unwrap(link.ep_b.ifid), out)
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


class AttachmentLink(NamedTuple):
    user_ifid: IfId                   # Interface ID in the user AS
    user_public_addr: UnderlayAddress # IP address and port the BR in the user AS is reachable at
    user_bind_addr: Optional[UnderlayAddress] # IP address and port the BR in the use AS listens on

    ap_id: ISD_AS                     # ISD-AS ID of the attachment point
    ap_public_addr: UnderlayAddress   # IP address and port the BR router in the AP is reachable at
    ap_bind_addr: Optional[UnderlayAddress] # IP address and port the BR in the AP listens on


def _get_ap_links(topo, user_as: AS) -> List[AttachmentLink]:
    """Get all links connecting a user AS to attachment points."""
    links = []

    for user_ifid, link in user_as.links():
        if link.is_dummy():
            continue
        elif topo.ases[link.ep_a].is_attachment_point:
            ap, user = link.ep_a, link.ep_b
            ap_underlay_addr, user_underlay_addr = link.ep_a_underlay, link.ep_b_underlay
        elif topo.ases[link.ep_b].is_attachment_point:
            ap, user = link.ep_b, link.ep_a
            ap_underlay_addr, user_underlay_addr = link.ep_b_underlay, link.ep_a_underlay
        else:
            continue # not an AP link
        links.append(AttachmentLink(
            user_ifid,
            unwrap(user_underlay_addr),
            link.bridge.get_br_bind_address(user, topo.ases[user], user_ifid),
            ap,
            unwrap(ap_underlay_addr),
            link.bridge.get_br_bind_address(ap, topo.ases[ap], ap.ifid)
        ))

    return links


def _format_underlay_addr(addr: Optional[UnderlayAddress]) -> Tuple[str, str]:
    """Returns an underlay address as a pair of IP address and port number as strings.

    The IP address is enclosed in single quotes. If `addr` is `None`, returns `(None, None)`.
    """
    if addr is not None:
        return "'%s'" % addr.ip, str(addr.port)
    else:
        return ("None", "None")


def fetch_api_secrets(topo, debug):
    """Retrieve coordinator API credentials for all ASes in the topology."""
    coord = topo.coordinator
    assert coord

    log.info("Fetching API secrets from coordinator.")
    try:
        cntr = coord.get_django_container()
    except errors.NotFound:
        log.error("Coordinator is not running.")
        raise

    secrets = io.StringIO()
    user = const.SCIONLAB_USER_DEBUG if debug else const.SCIONLAB_USER_PRODUCTION
    cmd = "./manage.py runscript print_api_secrets"
    run_cmd_in_cntr(cntr, user, cmd, output=secrets, check=True)
    coord.api_credentials = _parse_api_secrets(secrets.getvalue())


def _parse_api_secrets(input: str) -> Dict[ISD_AS, ApiCredentials]:
    """Parse the output of the 'print_api_secrets.py' script running in context of the coordinator.
    """
    output = {}

    for line in input.splitlines():
        isd_as_str, uid, secret = line.split()
        output[ISD_AS(isd_as_str)] = ApiCredentials(uid, secret)

    return output
