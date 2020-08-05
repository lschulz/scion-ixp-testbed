"""Helper functions for dealing with Docker."""

import io
import logging
import os
from pathlib import Path
import tarfile
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union

import docker

from ixp_testbed import errors

log = logging.getLogger(__name__)


def format_published_ports(ports: Dict[str, Tuple[str, str]]) -> str:
    """Format a dictionary of container to host port mappings as command line arguments for
    'docker create' or 'docker run'.
    """
    args = []
    for cntr_port, (host_ip, host_port) in ports.items():
        args.append("-p %s:%s:%s" % (host_ip, host_port, cntr_port))
    return " ".join(args)


def start_scion_cntr(dc: docker.DockerClient, image: str, *,
    cntr_name: str,
    mount_dir: Optional[Path] = None,
    ports: Mapping[str, Tuple[str, str]] = {},
    additional_args: Mapping[str, Any] = {}):
    """Create and run a dockerized SCION AS.

    :param dc: Docker client.
    :param image: Docker image the container is created from.
    :param cntr_name: Name of the new container.
    :param mount_dir: Directory in which the the gen folder and logs of the AS are stored.
                      If `None`, no host directories are mounted in the container.
    :param ports: Published ports as expected by `dc.containers.run`.
    :param additional_args: Additional arguments passed to `dc.containers.run`.
    :return: Docker container.
    """
    volumes = {}
    if mount_dir is not None:
        for dir in ["gen", "logs", "gen-cache", "gen-certs"]:
            host_dir = mount_dir.joinpath(dir)
            os.makedirs(host_dir, exist_ok=True)
            volumes[str(host_dir)] = {
                'bind': "/home/scion/go/src/github.com/scionproto/scion/" + dir,
                'mode': 'rw'
            }

    return dc.containers.run(
        image,
        name=cntr_name,
        tty=True,
        detach=True,
        ports=ports,
        volumes=volumes,
        **additional_args
    )


def copy_to_container(container, host_path: Path, cntr_path: Union[str, Path]) -> None:
    """
    Copy files from the host into a container.

    :param container: The container to copy to.
    :param host_path: Source path on the host. Directories are copied recursiveley.
    :param cntr_path: Destination path in the container.
    :raises CommandFailed: Copying failed.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tar:
        tar.add(str(host_path), arcname=host_path.name)
    if not container.put_archive(cntr_path, buffer.getvalue()):
        log.error("Copying %s to %s in container %s failed.", host_path, cntr_path, container.id)
        raise errors.CommandFailed()


def run_cmd_in_cntr(container, user: str, command: str, *,
    output = None, check: bool = False) -> int:
    """Run a command in bash within a container.

    :param container: Container to run the command in.
    :param user: Name of the user to execute the command as.
    :param command: The command to execute. Must not contain unescaped single quotes.
    :param output: Optional text stream the command's output is written to.
    :param check: If true, a `CommandFailed` exception is raised if the commands exits with a
                  non-zero value.
    :raises CommandFailed:
    :returns: Exit code of the command.
    """
    exit_code, response = container.exec_run(
        "/bin/bash -l -c '{}'".format(command), user=user, tty=True)

    decoded_response = response.decode('utf-8')
    level = logging.DEBUG if exit_code == 0 else logging.ERROR
    log.log(level, "Ran '%s' as '%s' in container %s:\n%s", command, user, container.name, decoded_response)

    if output is not None:
        output.write(decoded_response)

    if check and exit_code != 0:
        raise errors.CommandFailed("Command '{}' failed.".format(command))

    return exit_code


def run_cmd_in_cntrs(containers: Iterable[Any], user: str, command: str, detach=False) -> None:
    """Run a command in multiple containers in parallel.

    :param containers: Containers to run the command in. Must not contain unescaped single quotes.
    :param user: User to run the command as.
    :param command: The command to run.
    :param detach: Run the command in the background, do not capture output for logging.
    """
    streams = []
    for container in containers:
        _, stream = container.exec_run(
            "/bin/bash -l -c '{}'".format(command), user=user,
            tty=not detach, stream=not detach, detach=detach)
        streams.append(stream)

    if not detach:
        for cntr, stream in zip(containers, streams):
            response = "".join(chunk.decode('utf-8') for chunk in stream)
            log.debug("Ran '%s' as '%s' in container %s:\n%s", command, user, cntr.name, response)


def run_cmds_in_cntrs(containers: Iterable[Any], user: str, commands: Iterable[str], detach=False) -> None:
    """Run a different command in each container in parallel.

    :param containers: Containers to run the command in.
    :param user: User to run the command as.
    :param commands: The commands to run. The commands must not contain unescaped single quotes.
                     Must have the same size as `containers`.
    :param detach: Run the command in the background, do not capture output for logging.
    """
    streams = []
    for container, command in zip(containers, commands):
        _, stream = container.exec_run(
            "/bin/bash -l -c '{}'".format(command), user=user,
            tty=not detach, stream=not detach, detach=detach)
        streams.append(stream)

    if not detach:
        for cntr, stream, command in zip(containers, streams, commands):
            response = "".join(chunk.decode('utf-8') for chunk in stream)
            log.debug("Ran '%s' as '%s' in container %s:\n%s", command, user, cntr.name, response)
