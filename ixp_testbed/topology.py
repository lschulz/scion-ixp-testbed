"""Classes holding the configuration and current state of the topology.
The class `Topology` is stored to disk to save state between command invocations.
"""
import logging
from pathlib import Path
import pickle
import shutil
import sys
from typing import Dict, List, Optional

import docker

from ixp_testbed.address import ISD_AS, IpNetwork
import ixp_testbed.constants as const
from ixp_testbed.coordinator import Coordinator
from ixp_testbed.host import Host, push_docker_image, scan_hosts
from ixp_testbed.network.bridge import (
    Bridge, connect_bridges, disconnect_bridges, get_published_ports)
from ixp_testbed.scion import AS, Link
from ixp_testbed.service import ContainerizedService
from ixp_testbed.util.docker import (
    run_cmd_in_cntr, run_cmd_in_cntrs, run_cmds_in_cntrs, start_scion_cntr)

log = logging.getLogger(__name__)


class Ixp:
    """Contains information on an IXP.

    :ivar bridge: The bridge handling this IXP's traffic.
    :ivar ases: ASes connected to the IXP.
    """
    def __init__(self, bridge: Bridge):
        self.bridge = bridge
        self.ases: Dict[ISD_AS, AS] = {}


class Topology:
    """Represents a testbed topology.

    :ivar name: Name of the topology. Set on command line.
    :ivar hosts: Mapping from host names to host data.
    :ivar ases: All ASes in the topology.
    :ivar ixps: Mapping from IXP name to `IXP` objects for all IXPs in the topology.
    :ivar links: List of all SCION links in the topology.
    :ivar bridges: Mapping from IP subnets to network bridges providing container connectivity.
    :ivar default_link_subnet: Default subnet to allocate IP addresses from, if subnets are not
                               specified per link.
    :ivar ipv6_enabled: Whether to enabled IPv6 in Docker.
    :ivar coordinator: The optional SCIONLab Coordinator managing the network.
    :ivar additional_services: Additional services to run in the network.
    """
    def __init__(self, name: Optional[str] = None):
        self.name: Optional[str] = name
        self.hosts: Dict[str, Host] = {}
        self.ases: Dict[ISD_AS, AS] = {}
        self.ixps: Dict[str, Ixp] = {}
        self.links: List[Link] = []
        self.bridges: List[Bridge] = []
        self.default_link_subnet: Optional[IpNetwork] = None
        self.ipv6_enabled = False
        self.coordinator: Optional[Coordinator] = None
        self.additional_services: List[ContainerizedService] = []


    def save(self, file_path) -> None:
        """Serialize this object and store it in a file at the given location."""
        with open(file_path, 'wb') as file:
            pickle.dump(self, file)


    @staticmethod
    def load(file_path) -> 'Topology':
        """Create an instance by deserializing from the given file."""
        with open(file_path, 'rb') as file:
            return pickle.load(file)


    def close_host_connections(self) -> None:
        """Close all SSH connections to host participating in the topology."""
        for host in self.hosts.values():
            host.close_session()


    def get_bridge_name(self, name: str) -> Bridge:
        """Get a network bridge by name.

        :raises KeyError: Bridge not found.
        """
        for bridge in self.bridges:
            if bridge.name == name:
                return bridge
        raise KeyError("No bridge named '%s'." % name)


    def get_bridge_subnet(self, subnet: IpNetwork) -> Bridge:
        """Get a network bridge by IP subnet.

        :raises KeyError: Bridge not found.
        """
        for bridge in self.bridges:
            if bridge.ip_network == subnet:
                return bridge
        raise KeyError("No bridge with subnet '%s'." % subnet)


    def get_name_prefix(self) -> str:
        """"Returns the name prefix to use for container, bridges, etc. genrated for the topology.
        """
        if self.name:
            return self.name + "-"
        else:
            return ""


    def get_coord_name(self) -> str:
        """Returns the name prefix for components of the SCIONLab Coordinator."""
        return self.get_name_prefix() + "coord"


    def get_cntr_name(self, isd_as: ISD_AS) -> str:
        """Returns the name of the container for the given AS."""
        return self.get_name_prefix() + isd_as.file_fmt()


    def gen_bridge_name(self) -> str:
        """Generates a name for a network bridge based on the name prefix and the current number of
        bridges."""
        return "{}link{}".format(self.get_name_prefix(), len(self.bridges))


    def create_bridges(self) -> None:
        """Create all bridges defined in the topology that do not currently exist."""
        for bridge in self.bridges:
            bridge.create()


    def remove_bridges(self) -> None:
        """Remove all bridges defined in the topology."""
        for bridge in self.bridges:
            bridge.remove()


    def start_containers(self, workdir: Path, sc: Path, push_images: bool) -> None:
        """Start all Docker containers of the topology and connect them with their network bridges.

        The network bridges must have been created when calling this method, e.g., by calling
        create_bridges(). If hosts participating in the topology do not have all Docker images
        needed to run the necessary containers, the images are transmitted to them.

        If the topology contains a coordinator, the coordinator is started and initialized.

        :param workdir: Directory containing the topology data.
        :param sc: Path to the root of the SCION source tree.
        :param push_images: Whether to upload local Docker images to other Docker hosts when they do
                            not have the images already.
        """
        if len(self.hosts) > 1 and push_images:
            self._push_docker_image(workdir)
            if self.coordinator.debug:
                self._push_coord_image(workdir)

        for isd_as, asys in self.ases.items():
            self._start_container(isd_as, asys, workdir, sc)

        if self.coordinator is not None:
            self.coordinator.start()
            self.coordinator.init(self, workdir) # Make sure the coordinator is initialized

        for service in self.additional_services:
            service.start(self, self.get_name_prefix(), workdir)


    def _start_container(self, isd_as: ISD_AS, asys: AS, workdir: Path, sc: Path) -> None:
        """Start the Docker container hosting the given AS and connect it to the necessary bridges.
        """
        dc = asys.host.docker_client

        # Check if container is already running
        if asys.container_id:
            try:
                cntr = dc.containers.get(asys.container_id)
            except docker.errors.NotFound:
                # container has been removed
                asys.container_id = None
            else:
                if cntr.status == "running":
                    return # container is already running
                elif cntr.status == 'paused':
                    cntr.unpause()
                    log.info("Unpaused container %s [%s] (%s).", cntr.name, asys.host.name, cntr.id)
                    return
                else:
                    if self._restart_container(cntr, isd_as, asys):
                        return # restart successful

        # Create and start a new container
        cntr_name = self.get_cntr_name(isd_as)
        ports = get_published_ports(isd_as, asys)
        for cntr_port, (host_ip, host_port) in ports.items():
            log.info("Exposing port %s of %s on %s:%s [%s].",
                cntr_port, cntr_name, host_ip, host_port, asys.host.name)

        cntr = None
        if asys.host.is_local:
            mount_dir = workdir.joinpath(isd_as.file_fmt()).resolve()
            if self.coordinator is not None:
                # Starting a new instance of the coordinator generates new configuration files,
                # certificates, etc. If there are configuration or cache files from a previous run,
                # we remove them here.
                shutil.rmtree(mount_dir.joinpath("gen"), ignore_errors=True)
                shutil.rmtree(mount_dir.joinpath("gen-cache"), ignore_errors=True)

            kwargs = {}
            if not asys.cpu_affinity.is_unrestricted():
                kwargs['cpuset_cpus'] = str(asys.cpu_affinity)
            cntr = start_scion_cntr(dc, const.AS_IMG_NAME,
                cntr_name=cntr_name,
                mount_dir=mount_dir,
                ports=ports,
                extra_args=kwargs
            )
            asys.container_id = cntr.id

        else: # Start container on a remote host
            kwargs = {}
            if not asys.cpu_affinity.is_unrestricted():
                kwargs['cpuset_cpus'] = str(asys.cpu_affinity)
            cntr = dc.containers.run(
                const.AS_IMG_NAME,
                name=cntr_name,
                tty=True, # keep the container running
                detach=True,
                ports=ports,
                **kwargs
            )
            asys.container_id = cntr.id

        log.info("Started container %s [%s] with ID %s.", cntr_name, asys.host.name, asys.container_id)

        if self.coordinator is None:
            # If the coordinator creates the gen folder, 'gen-certs.sh' is invoked by
            # 'scionlab-config-user'.
            # If the topology is generated by 'scion.sh topology', we create the certificates
            # now.
            run_cmd_in_cntr(cntr, const.SCION_USER, "./gen-certs.sh", check=True)
        else:
            # Connect the new container to the coordinator.
            self.coordinator.bridge.connect(isd_as, asys)
            if asys.is_attachment_point or self.coordinator.ssh_management:
                # Allow the coordinator to access the container via SSH.
                self._authorize_coord_ssh_key(cntr, workdir)
                self._start_sshd(cntr)

        # Connect bridges SCION links.
        connect_bridges(isd_as, asys)


    def stop_containers(self) -> None:
        """Stop and remove all containers created by start_containers()."""
        for service in self.additional_services:
            service.stop()

        if self.coordinator is not None:
            self.coordinator.stop()

        for isd_as, asys in self.ases.items():
            self._stop_container(isd_as, asys)


    def _stop_container(self, isd_as: ISD_AS, asys: AS) -> None:
        """Stop the Docker container hosting the given AS."""
        if asys.container_id:
            dc = asys.host.docker_client
            try:
                cntr = dc.containers.get(asys.container_id)
            except docker.errors.NotFound:
                asys.container_id = None
            else:
                # Disconnect bridges not created by Docker here, to avoid leaving
                # unused interfaces behind when stopping the container.
                disconnect_bridges(isd_as, asys, non_docker_only=True)
                cntr.remove(force=True)
                log.info("Stopped container %s [%s] (%s).", cntr.name, asys.host.name, asys.container_id)
                asys.container_id = None


    def _restart_container(self, cntr, isd_as: ISD_AS, asys: AS) -> bool:
        """Try to restart an AS container currently not running.

        :param cntr: Container to restart.
        :param isd_as: AS the container belongs to.
        :param asys: AS the container belongs to.
        :returns: True, if container is now running. False, if the restart failed.
        """
        cntr.start() # try to start the container
        cntr.reload() # get the new status
        if cntr.status == "running":
            log.info("Restarted container %s [%s] (%s).", cntr.name, asys.host.name, asys.container_id)

            # Delete the socket used by the supervisor so scion.sh knows it has to be restarted.
            # See supervisor/supervisor.sh in the SCION source code.
            run_cmd_in_cntr(cntr, const.SCION_USER, "rm /tmp/supervisor.sock")

            # Network bridges not created by Docker don't reconnect automatically.
            disconnect_bridges(isd_as, asys, non_docker_only=True)
            connect_bridges(isd_as, asys, non_docker_only=True)

            # Restart the SSH server in managed ASes.
            if self.coordinator is not None:
                if asys.is_attachment_point or self.coordinator.ssh_management:
                    dc = asys.host.docker_client
                    self._start_sshd(dc.container.get(asys.container_id))

            return True # container is now running
        else:
            log.warning("Restarting container %s [%s] (%s) failed.", cntr.name, asys.host.name, asys.container_id)
            asys.container_id = None
            return False


    @staticmethod
    def _authorize_coord_ssh_key(cntr, workdir):
        """Copy to coordinator's public key to the authorized_keys file in the given container."""
        with open(workdir.joinpath(const.COORD_KEY_PATH, const.COORD_PUBLIC_KEY_FILE), 'r') as public_key:
            cmd = "umask 077 && mkdir -p ~/.ssh && echo \"%s\" >> ~/.ssh/authorized_keys" % public_key.read()
            run_cmd_in_cntr(cntr, const.SCION_USER, cmd, check=True)


    @staticmethod
    def _start_sshd(cntr):
        """Start the SSH server in the given container."""
        log.info("Starting sshd in %s.", cntr.name)
        run_cmd_in_cntr(cntr, "root", "mkdir -p /var/run/sshd")
        run_cmd_in_cntr(cntr, "root", "/usr/sbin/sshd", check=True)


    def run_scion(self) -> None:
        """Start SCION in all containers of the given topology.

        The containers must all be running. The topology's containers can be stated by calling
        start_containers().

        :raises docker.errors.NotFound: An AS container was not found, e.g., because it has been
                                        deleted.
        """
        log.info("Starting SCION...")

        for isd_as, asys in self.ases.items():
            if asys.container_id:
                self.run_scion_asys(isd_as, asys)

        log.info("Started SCION in all containers.")


    def run_scion_parallel(self, *, detach=False) -> None:
        """Like run_scion(), but starts SCION in all containers in parallel instead of one by one.

        :param detach: Do not wait for SCION to complete starting. No command output is logged.
        """
        log.info("Starting SCION...")

        cntrs = [self._get_container(isd_as, asys)
                 for isd_as, asys in self.ases.items() if asys.container_id]

        if self.coordinator is not None:
            coord = self.coordinator
            commands = [coord.get_config_cmd(isd_as)
                        for isd_as, asys in self.ases.items() if asys.container_id]
            run_cmds_in_cntrs(cntrs, const.SCION_USER, commands, detach)
        else:
            run_cmd_in_cntrs(cntrs, const.SCION_USER, "./scion.sh run nobuild", detach)

        log.info("Started SCION in all containers.")


    def run_scion_asys(self, isd_as: ISD_AS, asys: AS):
        """Start a single SCION AS.

        :param isd_as: AS to start.
        :param asys: AS to start.
        """
        cntr = self._get_container(isd_as, asys)
        if self.coordinator is not None:
            run_cmd_in_cntr(cntr, const.SCION_USER, self.coordinator.get_config_cmd(isd_as))
        else:
            run_cmd_in_cntr(cntr, const.SCION_USER, "./scion.sh run nobuild")


    def stop_scion(self):
        """Start SCION in all containers."""
        log.info("Stopping SCION...")

        for isd_as, asys in self.ases.items():
            if asys.container_id:
                self.stop_scion_asys(isd_as, asys)

        log.info("Stopped SCION in all containers.")


    def stop_scion_parallel(self, *, detach=False):
        """Like `run_scion()`, but stops SCION in all containers in parallel instead of one by one.

        :param detach: Do not wait for SCION to complete stopping. No command output is logged.
        """
        log.info("Stopping SCION...")

        cntrs = [self._get_container(isd_as, asys)
                 for isd_as, asys in self.ases.items() if asys.container_id]
        run_cmd_in_cntrs(cntrs, const.SCION_USER, "./scion.sh stop", detach)

        log.info("Stopped SCION in all containers.")


    def stop_scion_asys(self, isd_as: ISD_AS, asys: AS):
        """Stop a single SCION AS.

        :param isd_as: AS to stop.
        :param asys: AS to stop.
        """
        cntr = self._get_container(isd_as, asys)
        run_cmd_in_cntr(cntr, const.SCION_USER, "./scion.sh stop")


    def is_scion_running(self, isd_as: ISD_AS, asys: AS) -> bool:
        """Check whether the container associated with the given AS is running all SCION services.
        """
        if not asys.container_id:
            return False

        cntr = None
        try:
            cntr = self._get_container(isd_as, asys)
        except docker.errors.NotFound:
            return False

        if cntr.status != "running":
            return False

        _, response = cntr.exec_run(
            "/bin/bash -l -c './scion.sh status'", user=const.SCION_USER, tty=True)

        return len(response) == 0 # if everything is running, there is no output


    def print_container_status(self, out=sys.stdout) -> None:
        """Retrieve status information from the coordinator and AS containers and print it to `out`.

        Retrieved status information includes container status and output of "scion.sh status"
        from all ASes.

        :param out: Text stream to print to.
        """
        if self.coordinator is not None:
            self.coordinator.print_status(out)

        for service in self.additional_services:
            status = "no container"
            cntr = service.get_container()
            if cntr is not None:
                out.write("### {}: {} ({})\n".format(service.name, cntr.status, cntr.name))
            else:
                out.write("### {}: no container\n".format(service.name))

        for isd_as, asys in self.ases.items():
            cntr_name = self.get_cntr_name(isd_as)
            cntr = None
            status = "no container"

            if asys.container_id:
                dc = asys.host.docker_client
                cntr = self._get_container_by_id(cntr_name, asys.container_id, dc)
                if cntr is not None:
                    status = cntr.status

            out.write("### AS{} : {} ({})\n".format(isd_as, status, cntr_name))
            if cntr and cntr.status == "running":
                exit_code, response = cntr.exec_run(
                    "/bin/bash -l -c './scion.sh status'", user=const.SCION_USER, tty=True)
                out.write(response.decode('utf-8'))


    def _push_docker_image(self, workdir: Path) -> None:
        """Make sure all remote host participating in the topology have the SCION AS image."""
        local_dc = self.hosts['localhost'].docker_client
        local_image = local_dc.images.get(const.AS_IMG_NAME)

        hosts = scan_hosts(self.hosts.values(), local_image)

        if len(hosts) != 0:
            push_docker_image(hosts, local_image,
                local_file = str(workdir.joinpath(const.AS_IMAGE_TAR_FILE)),
                remote_file = const.REMOTE_AS_IMAGE_TAR_FILE)


    def _push_coord_image(self, workdir: Path) -> None:
        """Make sure the host which is supposed to run the coordinator has the coordinator image."""
        if self.coordinator.host.is_local:
            return

        local_dc = self.hosts['localhost'].docker_client
        local_image = local_dc.images.get(const.COORD_IMG_NAME)

        hosts = scan_hosts([self.coordinator.host], local_image)

        if len(hosts) != 0:
            push_docker_image(hosts, local_image,
                local_file = str(workdir.joinpath(const.COORD_IMAGE_TAR_FILE)),
                remote_file = const.REMOTE_COORD_IMAGE_TAR_FILE)


    @staticmethod
    def _get_container_by_id(name: str, id: str, dc: docker.DockerClient):
        try:
            return dc.containers.get(id)
        except docker.errors.NotFound:
            log.warning("Container %s (%s) not found.", name, id)
            return None


    def _get_container(self, isd_as: ISD_AS, asys: AS):
        """Get the container hosting the given AS.

        :returns: Docker container object.
        :raises docker.errors.NotFound: The container associated with the AS does not exist anymore.
                                        This error has been logged and the stale container ID deleted.
        """
        dc = asys.host.docker_client
        try:
            return dc.containers.get(asys.container_id)
        except docker.errors.NotFound:
            cntr_name = self.get_cntr_name(isd_as)
            log.error("Container %s [%s] (%s) not found.", cntr_name, asys.host.name, asys.container_id)
            asys.container_id = None
            raise
