import logging
import os
from pathlib import Path
from typing import Iterator, List, Optional, cast

import yaml

from ixp_testbed.address import ISD_AS, IpAddress, UnderlayAddress
from ixp_testbed.coordinator import Coordinator
from ixp_testbed.host import Host, RemoteHost
from ixp_testbed.network.docker import DockerNetwork
from ixp_testbed.service import ContainerizedService
from ixp_testbed.util.cpu_affinity import CpuSet
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)

_PROMETHEUS_CONFIG_FILE = "prometheus.yml"
"""Name of the Prometheus configuration file."""

_CS_PROM_PORT = 30454
"""Port of the Prometheus metrics endpoint of the control service."""

_SD_PROM_PORT = 30455
"""Prometheus port of sciond."""

_DISPATCHER_PROM_PORT = 30441
"""Prometheus port of the dispatcher."""


class Prometheus(ContainerizedService):
    """Represents a Prometheus server.

    :ivar exposed_at: Host address the server is reachable at.
    :ivar scrape_interval: Interval in which metrics are collected.
    :ivar storage_dir: Optional host directory to bind-mount into the container as storage directory.
    :ivar targets: List of ASes to collect metric from.
    :ivar _config_path: Path to the Prometheus server configuration file.
    """
    _PROM_SERVER = "prometheus"

    def __init__(self, host: Host, bridge: DockerNetwork, *,
        scrape_interval: str = "30s", storage_dir: Optional[Path] = None,
        targets: List[ISD_AS] = [],
        cpu_affinity: CpuSet = CpuSet()):
        """
        :param host: Host the server is ran on.
        """
        super().__init__(host, bridge, cpu_affinity)
        self.exposed_at: Optional[UnderlayAddress] = None
        self.scrape_interval = scrape_interval
        self.storage_dir = storage_dir
        self.targets = targets
        self._config_path: Optional[str] = None

    @property
    def name(self):
        return "Prometheus"

    def reserve_ip_addresses(self, ip_gen: Optional[Iterator[IpAddress]] = None):
        self.bridge.assign_ip_address(self._PROM_SERVER,
            next(ip_gen) if ip_gen is not None else None)

    def start(self, topo, name_prefix: str, workdir: Path):
        if self._sync_container_status():
            return # Container is running already.

        if self.host.is_local:
            # Create prometheus configuration file in the topology work directory.
            config_path = workdir.joinpath(_PROMETHEUS_CONFIG_FILE).resolve() # need absolute path
            log.debug("Writing Prometheus configuration to '%s'.", config_path)
            with open(config_path, 'w') as config:
                config.write(self._create_config(topo.coordinator))
        else:
            # Create Prometheus configuration file in temporary directory.
            remote_host = cast(RemoteHost, self.host)
            result = remote_host.run_cmd(["mktemp", "-d", "-q"], check=True, capture_output=True)
            temp_dir = result.output.strip()
            config_path = os.path.join(temp_dir, _PROMETHEUS_CONFIG_FILE)

            log.debug("Writing Prometheus configuration to '%s' on host %s.",
                config_path, remote_host.name)
            with remote_host.open_file(config_path, mode='w') as config:
                config.write(self._create_config(topo.coordinator).encode('utf-8'))

        self._config_path = str(config_path)

        if self.exposed_at is not None:
            ports = {"9090/tcp": (str(self.exposed_at.ip), self.exposed_at.port)}
            log.info("Exposing prometheus at http://%s", self.exposed_at.format_url())
        else:
            ports = {}

        cntr_name = name_prefix + "prom"
        volumes={config_path: {'bind': "/etc/prometheus/prometheus.yml", 'mode': 'ro'}}
        if self.storage_dir is not None:
            if self.host.is_local:
                # Try to resolve relative paths on localhost.
                storage_dir = str(self.storage_dir.resolve())
                os.makedirs(storage_dir, exist_ok=True)
            else:
                # Remote paths must be absolute.
                storage_dir = str(self.storage_dir)
            log.info("Prometheus database is stored in '%s'." % storage_dir)
            volumes[storage_dir] = {'bind': "/prometheus", 'mode': 'rw'}

        args = {
            'command': ["--config.file=/etc/prometheus/prometheus.yml"],
            'name': cntr_name,
            'volumes': volumes,
            'ports': ports,
            'detach': True
        }
        if self.storage_dir is not None:
            args['user'] = "%d:%d" % (self.host.getuid(), self.host.getgid())
        self._run_container("prom/prometheus:latest", **args)

        self.bridge.connect_container(self.get_container(),
            unwrap(self.bridge.get_ip_address(self._PROM_SERVER)), self.host)

        log.info("Started Prometheus %s [%s] (%s).", cntr_name, self.host.name, self.container_id)


    def stop(self):
        cntr = self._stop_container()
        if cntr is None:
            return # No container to stop.

        log.info("Stopped Prometheus %s [%s] (%s).", cntr.name, self.host.name, cntr.id)

        if not self.host.is_local and self._config_path is not None:
            # Delete temporary files.
            remote_host = cast(RemoteHost, self.host)
            if not remote_host.delete_file(self._config_path):
                log.warning("Could not delete file %s on host %s.", self._config_path, self.host.name)
            dir_name = os.path.dirname(self._config_path)
            if not remote_host.rmdir(dir_name):
                log.warning("Could not delete directory %s on host %s.", dir_name, self.host.name)
            self._config_path = None


    def _create_config(self, coord: Coordinator) -> str:
        """Create the server configuration.

        :returns: Prometheus server configuration.
        """
        config = {}
        config['global'] = {'scrape_interval': self.scrape_interval}

        scrape_configs = []
        for target in self.targets:
            ip = self.bridge.get_ip_address(target)
            if ip is None:
                log.error("No IP address for AS %s in network %s.", target, self.bridge)
                continue

            br_ports = coord.get_br_prom_ports(target)
            static_configs = [
                _static_target(ip, _CS_PROM_PORT, "cs"),
                _static_target(ip, _SD_PROM_PORT, "sd"),
                _static_target(ip, _DISPATCHER_PROM_PORT, "disp"),
                {
                    'targets': ["[%s]:%d" % (ip, port) for port in br_ports],
                    'labels': {'group': "br"}
                }
            ]

            scrape_configs.append({
                'job_name': target.as_str(),
                'static_configs': static_configs,
            })

        config['scrape_configs'] = scrape_configs
        return yaml.dump(config, indent=2)


def _static_target(ip: IpAddress, port: int, group: str):
    return {
        'targets': ["[%s]:%d" % (ip, port)],
        'labels': {'group': group}
    }
