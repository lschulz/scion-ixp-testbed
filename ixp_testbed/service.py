from abc import ABC, abstractmethod
import logging
from pathlib import Path
from typing import Optional

import docker

log = logging.getLogger(__name__)


class ContainerizedService(ABC):
    """Abstract base class for additional services included in the topology.

    :ivar host: Docker host the service is ran on.
    :ivar container_id: ID of the Docker container hosting the service, if any.
    """
    def __init__(self, host):
        self.host = host
        self.container_id: Optional[str] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the service."""
        raise NotImplementedError()

    @abstractmethod
    def start(self, name_prefix: str, workdir: Path) -> None:
        """Start the service.

        :param name_prefix: Name prefix for the container name.
        :param workdir: The topology's work directory.
        """
        raise NotImplementedError()

    @abstractmethod
    def stop(self) -> None:
        """Stop the service."""
        raise NotImplementedError()

    def get_container(self):
        """Get the container the service is running in.

        :returns: `None`, if the service is not running.
        """
        try:
            return self.host.docker_client.containers.get(self.container_id)
        except docker.errors.NotFound:
            log.error("Container with ID %s is gone.", self.container_id)
            self.container_id = None
            return None


    def _sync_container_status(self) -> bool:
        """Make sure `self.container_id` either refers to a running container or is `None`.

        Resets `container_id` to `None`, if the container is gone.
        Removes stale containers, to prepare for restarting the service.

        :returns: True if the container is running, false if not.
        """
        if self.container_id:
            # Check wheather the container is already running
            dc = self.host.docker_client
            try:
                cntr = dc.containers.get(self.container_id)
            except docker.errors.NotFound:
                self.container_id = None
            else:
                if cntr.status == 'running':
                    return True # already running
                else:
                    # Remove old container
                    cntr.stop()
                    cntr.remove()
                    self.container_id = None
        return False


    def _run_container(self, *args, **kwargs):
        """Calls `containers.run(*args, **kwargs)` and stores the container ID in
        `self.container_id`.

        :returns: Newly created container.
        """
        dc = self.host.docker_client
        cntr = dc.containers.run(*args, **kwargs)
        self.container_id = cntr.id
        return cntr


    def _stop_container(self):
        """Stops and removes the container identified by `self.container_id`, if any.

        :returns: Stopped container, or `None`, if there is no container to stop.
        """
        if self.container_id is not None:
            dc = self.host.docker_client
            try:
                cntr = dc.containers.get(self.container_id)
            except docker.errors.NotFound:
                self.container_id = None
            else:
                cntr.stop()
                cntr.remove()
                self.container_id = None
                return cntr
        return None
