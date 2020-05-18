import logging
import os
from pathlib import Path
from typing import List, Optional, cast

import yaml

from ixp_testbed.address import ISD_AS, UnderlayAddress
from ixp_testbed.host import Host, RemoteHost
from ixp_testbed.network.docker import DockerNetwork
from ixp_testbed.service import ContainerizedService

log = logging.getLogger(__name__)


PROMETHEUS_CONFIG_FILE = "prometheus.yml"
"""Name of the Prometheus configuration file."""

CS_PROM_PORT = 30454
"""Port of the Prometheus metrics endpoint of the control service."""


class Prometheus(ContainerizedService):
    """Represents a Prometheus server.

    :ivar bridge: Network for communication with ASes.
    :ivar exposed_at: Host address the server is reachable at.
    :ivar scrape_interval: Interval in which metrics are collected.
    :ivar targets: List of ASes to collect metric from.
    :ivar _config_path: Path to the Prometheus server configuration file.
    """
    def __init__(self, host: Host, bridge: DockerNetwork, *,
        scrape_interval: str = "30s", targets: List[ISD_AS] = []):
        """
        :param host: Host the server is ran on.
        """
        super().__init__(host)
        self.bridge = bridge
        self.exposed_at: Optional[UnderlayAddress] = None
        self.scrape_interval = scrape_interval
        self.targets = targets
        self._config_path: Optional[str] = None

    @property
    def name(self):
        return "Prometheus"

    def start(self, name_prefix: str, workdir: Path):
        if self._sync_container_status():
            return # Container is running already.

        if self.host.is_local:
            # Create prometheus configuration file in the topology work directory.
            config_path = workdir.joinpath(PROMETHEUS_CONFIG_FILE).resolve() # need absolute path
            log.debug("Writing Prometheus configuration to '%s'.", config_path)
            with open(config_path, 'w') as config:
                config.write(self._create_config())
        else:
            # Create Prometheus configuration file in temporary directory.
            remote_host = cast(RemoteHost, self.host)
            result = remote_host.run_cmd(["mktemp", "-d", "-q"], check=True, capture_output=True)
            temp_dir = result.output.strip()
            config_path = os.path.join(temp_dir, PROMETHEUS_CONFIG_FILE)

            log.debug("Writing Prometheus configuration to '%s' on host %s.",
                config_path, remote_host.name)
            with remote_host.open_file(config_path, mode='w') as config:
                config.write(self._create_config().encode('utf-8'))

        self._config_path = str(config_path)

        if self.exposed_at is not None:
            ports = {"9090/tcp": (str(self.exposed_at.ip), self.exposed_at.port)}
            log.info("Exposing prometheus at http://%s", self.exposed_at.format_url())
        else:
            ports = {}

        cntr_name = name_prefix + "prom"
        self._run_container("prom/prometheus:latest",
            command=["--config.file=/etc/prometheus/prometheus.yml"],
            name=cntr_name,
            volumes={config_path: {'bind': "/etc/prometheus/prometheus.yml", 'mode': 'ro'}},
            network=str(self.bridge.docker_id),
            ports=ports,
            detach=True)

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


    def _create_config(self) -> str:
        """Create the server configuration.

        :returns: Prometheus server configuration.
        """
        config = {}
        config['global'] = {'scrape_interval': self.scrape_interval}

        static_configs = []
        for target in self.targets:
            ip = self.bridge.get_ip_address(target)
            if ip is None:
                log.error("No IP address for AS %s in network %s.", target, self.bridge)
                continue
            static_configs.append({
                'targets': [
                    "[%s]:%d" % (ip, CS_PROM_PORT)
                ],
                'labels': {'group': target.as_str()}
            })

        scrape_config = {
            'job_name': 'scion-ixp-testbed',
            'static_configs': static_configs,
        }
        config['scrape_configs'] = [scrape_config]

        return yaml.dump(config, indent=2)
