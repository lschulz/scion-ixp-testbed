"""Helper functions for dealing with Docker."""

import io
import logging
import os
from pathlib import Path
import subprocess
import tarfile
from typing import Any, Dict, Iterable, Tuple, Union

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


def invoke_scion_docker_script(sc: Path, subcommand: str, env_arg: Dict[str, Any] = {}) -> None:
    """Invoke the "docker.sh" script found in the SCION root directory.

    :param sc: Path to the root of the SCION source tree.
    :param subcommand: The subcommand of docker.sh to execute.
    :param env_arg: Additional environment variables to set up for docker.sh.
    :raises CommandFailed: docker.sh return a non-zero value.
    """
    env = dict(os.environ, **env_arg)
    result = subprocess.run(["./docker.sh", subcommand], cwd=sc, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')

    level = logging.DEBUG if result.returncode == 0 else logging.ERROR
    log.log(level, "Ran './docker.sh %s':\n%s", subcommand, result.stdout)

    if result.returncode != 0:
        raise errors.CommandFailed("./docker.sh failed.")


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
