from abc import ABC, abstractmethod
import gzip
import inspect
import io
import logging
import os
from pathlib import Path
import socket
import subprocess
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, cast

import docker
import gevent
from pssh.clients.native import ParallelSSHClient
import ssh2.exceptions
from ssh2.knownhost import (
    LIBSSH2_KNOWNHOST_KEYENC_RAW, LIBSSH2_KNOWNHOST_KEY_SSHDSS,
    LIBSSH2_KNOWNHOST_KEY_SSHRSA, LIBSSH2_KNOWNHOST_TYPE_PLAIN)
from ssh2.session import LIBSSH2_HOSTKEY_TYPE_RSA, Session

from ixp_testbed import errors
from ixp_testbed.address import IpAddress, L4Port, UnderlayAddress
from ixp_testbed.constants import KNOWN_HOSTS_FILE

log = logging.getLogger(__name__)


class CompletedProcess(NamedTuple):
    exit_code: int
    output: Optional[str] = None


class Host(ABC):
    """Abstract base class for Docker hosts.
    """
    @property
    @abstractmethod
    def name(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def docker_client(self) -> docker.DockerClient:
        """Returns a Docker client instance connected to the host."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def is_local(self) -> bool:
        """Whether this is the local computer."""
        raise NotImplementedError()

    @abstractmethod
    def run_cmd(self, args: List[str], *,
        check:bool = False, capture_output:bool = False) -> CompletedProcess:
        """Run a command on the host.

        :param args: List of the command and its arguments.
        :param check: If true the exit code of the command is checked. If it is not zero, a
                      ProcessError exception is raised.
        :param capture_output: If true, the commands output is captures and returns in the return
                               value or ProcessError exception.
        :returns: The command's exit code and a concatenation of stdout and stderr output if
                  `capture_output` is true.
        :raises ProcessError: The command returned value not equal to zero and `check` is true.
        """
        raise NotImplementedError()

    @abstractmethod
    def close_session(self) -> None:
        """Close all SSH sessions with the host."""
        raise NotImplementedError()


class LocalHost(Host):
    """Represents the local computer.

    :ivar _dc: Cached Docker client.
    """
    def __init__(self):
        self._dc: docker.DockerClient = None

    def __getstate__(self):
        state = self.__dict__.copy()
        state['_dc'] = None # don't attempt to serialize the Docker client
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._dc = None

    @property
    def name(self):
        return "localhost"

    @property
    def docker_client(self) -> docker.DockerClient:
        if self._dc is None:
            # A higher timeout is needed for saving large images to disk. See push_docker_image().
            self._dc = docker.from_env(timeout=120)
        return self._dc

    @property
    def is_local(self):
        return True

    def run_cmd(self, args: List[str], *,
        check:bool = False,
        capture_output:bool = False) -> CompletedProcess:
        """
        :returns: Either the exit code or a pair of exit code and captured output.
        """
        if capture_output:
            result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    encoding='utf-8')
            if check and result.returncode != 0:
                raise errors.ProcessError(result.returncode, result.stdout)
            else:
                return CompletedProcess(result.returncode, result.stdout)
        else:
            result = subprocess.run(args)
            if check and result.returncode != 0:
                raise errors.ProcessError(result.returncode)
            else:
                return CompletedProcess(result.returncode)

    def close_session(self):
        if self._dc is not None:
            self._dc.close()
            self._dc = None


class RemoteHost(Host):
    """A remote host offering SSH access and running the Docker daemon.

    AS containers are distributed over available host according to the topology definition.

    :ivar _name: A name used to refer to the host in context of this program.
    :ivar _ssh_host: IP address for SSH access.
    :ivar _ssh_port: The port the SSH server listens on.
    :ivar _username: The username for logging in to the remote host. run_cmd() executes commands as
                     this user.
    :ivar _identity_file: The location of the private key to be used for login. If no key is given,
                          ssh-agent is used for authentication.
    :ivar _ssh_session: Cached SSH connection.
    :ivar _sftp_session: Cached SFTP session.
    :ivar _dc: Cached Docker client.
    """
    def __init__(self, name: str, ssh_host: IpAddress, username: str, *,
        identity_file: Optional[Path] = None,
        ssh_port: L4Port = L4Port(22)):
        self._name = name
        self._ssh_host = ssh_host
        self._ssh_port = ssh_port
        self._username = username
        self._identity_file = identity_file
        self._ssh_session: Optional[Session] = None
        self._sftp_session: Optional[ssh2.sftp.SFTP] = None
        self._dc: docker.DockerClient = None

    def __getstate__(self):
        state = self.__dict__.copy()
        # Don't attempt to serialize the SSH session or Docker client.
        state['_ssh_session'] = None
        state['_sftp_session'] = None
        state['_dc'] = None
        return state

    @property
    def name(self):
        return self._name

    @property
    def is_local(self):
        return False

    @property
    def docker_client(self) -> docker.DockerClient:
        if self._dc is None:
            url = "ssh://%s@%s" % (
                self._username, UnderlayAddress(self._ssh_host, self._ssh_port).format_url())
            self._dc = docker.DockerClient(base_url=url)

        return self._dc

    @property
    def ssh_host(self) -> IpAddress:
        return self._ssh_host

    def get_host_config(self) -> Dict[str, Any]:
        """Get a host configuration dictionary compatible with parallel-ssh."""
        config = {
            'user': self._username,
            'port': self._ssh_port,
        }
        if self._identity_file is not None:
            config['private_key'] = str(self._identity_file)
        return config

    def run_cmd(self, args: List[str], *,
        check:bool = False,
        capture_output:bool = False) -> CompletedProcess:

        channel = self._get_ssh_session().open_session()
        assert channel != 0
        try:
            cmd = " ".join(args)
            log.debug("Running '%s' on '%s'.", cmd, self.name)
            channel.execute(cmd)
            channel.wait_eof()
        finally:
            channel.close()
            channel.wait_closed()

        exit_code = channel.get_exit_status()

        output = None
        if capture_output:
            buffer = io.BytesIO()
            self._read_from_channel(channel, buffer, 0) # read stdout
            self._read_from_channel(channel, buffer, 1) # read stderr
            output = str(buffer.getvalue(), encoding='utf-8')

        if check and exit_code != 0:
            raise errors.ProcessError(exit_code, output)
        else:
            return CompletedProcess(exit_code, output)


    def mkdir(self, path, mode=0o777):
        """Create a directory on the remote host.

        :param path: Path of the new directory.
        :param mode: Permissions the directory is created with.
        :returns: True on success, false on failure.
        """
        sftp = self._get_sftp_session()
        res = sftp.mkdir(path, mode)
        return self._ssh2_check_success(res)


    def rmdir(self, path):
        """Remove a directory om the remote host.

        :param path: Path to the directory to be deleted.
        :returns: True on success, false on failure.
        """
        sftp = self._get_sftp_session()
        res = sftp.rmdir(path)
        return self._ssh2_check_success(res)


    def open_file(self, filename, mode='r', file_mode=0o644):
        """Open a file on the remote host.

        :param filename: Path to the file.
        :param mode: Mode in which the file is opened. Similar to built-in function `open`.
        :param file_mode: Permissions a new file is created with.
        """
        flags = 0
        if 'r' in mode:
            flags |= ssh2.sftp.LIBSSH2_FXF_READ
        if 'w' in mode:
            flags |= ssh2.sftp.LIBSSH2_FXF_WRITE | ssh2.sftp.LIBSSH2_FXF_CREAT
        if 'a' in mode:
            flags |= ssh2.sftp.LIBSSH2_FXF_APPEND | ssh2.sftp.LIBSSH2_FXF_CREAT
        if 'x' in mode:
            flags |= ssh2.sftp.LIBSSH2_FXF_EXCL | ssh2.sftp.LIBSSH2_FXF_CREAT
        if 't' in mode:
            flags |= ssh2.sftp.LIBSSH2_FXF_TRUNC | ssh2.sftp.LIBSSH2_FXF_CREAT

        sftp = self._get_sftp_session()
        return sftp.open(filename, flags, file_mode)


    def delete_file(self, filename):
        """Delete a file on the remote host.

        :param filename: Path to the file.
        :returns: True on success, false on failure.
        """
        sftp = self._get_sftp_session()
        res = sftp.unlink(filename)
        return self._ssh2_check_success(res)


    @staticmethod
    def _ssh2_check_success(ret):
        # Interpret LIBSSH2_ERROR_EAGAIN as success.
        return ret == 0 or ret == ssh2.error_codes.LIBSSH2_ERROR_EAGAIN


    def _get_ssh_session(self):
        if self._ssh_session is None:
            self._ssh_session = self._establish_ssh_session()
        return self._ssh_session


    def _get_sftp_session(self):
        if self._sftp_session is None:
            self._sftp_session = self._get_ssh_session().sftp_init()
        return self._sftp_session


    def _establish_ssh_session(self):
        # Connect to remote host.
        try:
            sock = socket.create_connection((str(self._ssh_host), self._ssh_port))
        except Exception:
            log.error("Cannot connect to host '%s' (%s, %d).",
                      self.name, self._ssh_host, self._ssh_port)
            raise

        # SSH handshake.
        ssh_session = Session()
        ssh_session.handshake(sock)

        # Verify host key. Accept keys from previously unknown hosts on first connection.
        hosts = ssh_session.knownhost_init()
        testbed_root = os.path.dirname(os.path.abspath(inspect.stack()[-1][1]))
        known_hosts_path = os.path.join(testbed_root, KNOWN_HOSTS_FILE)
        try:
            hosts.readfile(known_hosts_path)
        except ssh2.exceptions.KnownHostReadFileError:
            pass # ignore, file is created/overwritten later

        host_key, key_type = ssh_session.hostkey()
        server_type = None
        if key_type == LIBSSH2_HOSTKEY_TYPE_RSA:
            server_type = LIBSSH2_KNOWNHOST_KEY_SSHRSA
        else:
            server_type = LIBSSH2_KNOWNHOST_KEY_SSHDSS
        type_mask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | server_type

        try:
            hosts.checkp(str(self._ssh_host).encode('utf-8'), self._ssh_port, host_key, type_mask)
        except ssh2.exceptions.KnownHostCheckNotFoundError:
            log.warn("Host key of '%s' (%s, %d) added to known hosts.",
                     self.name, self._ssh_host, self._ssh_port)
            hosts.addc(str(self._ssh_host).encode('utf-8'), host_key, type_mask)
            hosts.writefile(known_hosts_path)
        except ssh2.exceptions.KnownHostCheckMisMatchError:
            log.error("Host key of '%s' (%s, %d) does not match known key.",
                      self.name, self._ssh_host, self._ssh_port)
            raise

        # Authenticate at remote host.
        try:
            if self._identity_file is None:
                ssh_session.agent_auth(self._username)
            else:
                ssh_session.userauth_publickey_fromfile(self._username, self._identity_file)
        except Exception:
            log.error("Authentication at host '%s' (%s, %d) failed.",
                        self.name, self._ssh_host, self._ssh_port)
            ssh_session.disconnect()
            raise

        return ssh_session


    @staticmethod
    def _read_from_channel(channel, buffer: io.BytesIO, stream_id: int) -> None:
        """Helper for storing the output of a completed command to buffer."""
        size, data = channel.read_ex(stream_id=stream_id)
        while size > 0:
            buffer.write(data)
            size, data = channel.read_ex(stream_id=stream_id)


    def close_session(self):
        if self._ssh_session is not None:
            self._ssh_session.disconnect()
            self._ssh_session = None
        if self._dc is not None:
            self._dc.close()
            self._dc = None


def scan_hosts(hosts: Iterable[Host], local_image) -> List[RemoteHost]:
    """Check which of the given host do not have `local_image`.

    :param hosts: Set of remote host to check.
    :param local_image: The image to query for as a Docker SDK image instance.
    :returns: List of host which do not have `local_image`.
    """
    hosts_to_update: List[RemoteHost] = []

    for host in filter(lambda h: not h.is_local, hosts):
        dc = host.docker_client
        update_image = False
        try:
            image = dc.images.get(local_image.id)
        except docker.errors.ImageNotFound:
            update_image = True
        else:
            update_image = image.id != local_image.id
        if update_image:
            hosts_to_update.append(cast(RemoteHost, host))

    return hosts_to_update


def push_docker_image(
    hosts: Iterable[RemoteHost], local_image, local_file: str, remote_file: str) -> None:
    """Push a local Docker image to a set of remote hosts.

    Does not verify host keys.

    :param hosts: Set of remote host to upload the image to.
    :param local_image: Instance of a Docker SDK image object corresponding to the image to
                        distribute.
    :param local_file: Path a temporary file the image is dumped to.
    :param remote_file: Path to use for a temporary image file on the remote host.
    """
    # Save local image to file.
    # Running "docker save %s | gzip > %s" %(local_image.id, local_file) on the host might be
    # faster, because the Python API seems to write a temporary file and then return it instead
    # of streaming the data.
    log.info("Writing image %s to file '%s'.", local_image.short_id, local_file)
    with gzip.open(local_file, 'wb') as file:
        for chunk in local_image.save(named=True):
            file.write(chunk)

    host_ips = [str(host.ssh_host) for host in hosts]
    host_config = {str(host.ssh_host): host.get_host_config() for host in hosts}

    log.info("Copying image %s to %s.", local_image.short_id,
        ", ".join("%s (%s)" % (h.name, h.ssh_host) for h in hosts))

    try:
        ssh_client = ParallelSSHClient(host_ips, host_config=host_config)

        # Copy image file to remote hosts.
        greenlets = ssh_client.scp_send(local_file, remote_file)
        # Not ideal: Waits until all hosts have the image before proceeding.
        gevent.joinall(greenlets, raise_error=True)

        # Load image from file.
        output = ssh_client.run_command("gunzip -c %s | docker image load" % remote_file)
        ssh_client.join(output)
        for host, host_output in output.items():
            buffer = io.StringIO()
            for line in host_output.stdout:
                print(line, file=buffer)
            level = logging.INFO if host_output.exit_code == 0 else logging.WARNING
            log.log(level, "%s responds:\n%s", host, buffer.getvalue())

        # Delete the image file.
        output = ssh_client.run_command("rm %s" % remote_file)
        ssh_client.join(output)

    except Exception:
        log.error("Pushing docker image to remote hosts failed.")
        raise
