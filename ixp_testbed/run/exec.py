"""Functions for executing commands in AS containers."""

import io
import logging
import re
import sys

import docker

from ixp_testbed.constants import SCION_USER
from ixp_testbed.topology import Topology

log = logging.getLogger(__name__)


def run_in_matching_cntrs(
    topo: Topology, as_pattern: str, cmd_template: str, user: str,
    detach: bool = False, dry_run: bool = False):
    """Run a command in all AS containers whose ISD-AS string matches `as_pattern`.

    :param topo: Topology database.
    :param as_pattern: Regular expression to match against ISD-AS strings like '1-ff00:0:110'.
    :param cmd_template: Command to execute. The template is formated using str.format() for each AS.
                         Availabile variables are: 'isd_as', 'file_fmt'
    :param user: User to run the command as.
    :param detach: If true, the command is detached from the Docker exec and no output is forwarded.
    :param dry_run: If true, the command is not actually executed, just printed to stdout.
    """
    try:
        regex = re.compile(as_pattern)
    except re.error:
        print("Invalid regular expression: '{}'".format(as_pattern))
        return
    for isd_as, asys in topo.ases.items():
        if regex.fullmatch(str(isd_as)):
            if not asys.container_id:
                print("No container for AS{}.".format(isd_as))
            else:
                try:
                    dc = asys.host.docker_client
                    cntr = dc.containers.get(asys.container_id)
                except docker.errors.NotFound:
                    cntr_name = topo.get_cntr_name(isd_as)
                    log.warning("Container {} ({}) not found.".format(cntr_name, asys.container_id))
                else:
                    cmd = cmd_template.format(isd_as=str(isd_as), file_fmt=isd_as.file_fmt())
                    if dry_run:
                        print("Would run '{}' in {}.".format(cmd, cntr.name))
                    else:
                        _run_in_cntr(cntr, cmd, user, detach)


def fetch_config(topo: Topology, as_pattern: str = '.*', detach: bool = True, force: bool = False):
    """Fetch the most recent configuration from the coordinator.

    :param topo: A topology containing a coordinator.
    :param as_pattern: All ASes matching this regular expression are updated.
    :param detach: If set to true, the program does not wait for the containers complete the
                   configuration update and no command output is printed to stdout.
    :param force: If true, the configuration is downloaded from the coordinator and installed, even
                  when the currently installed configuration should be up to date.
    """
    cmd = io.StringIO()
    cmd.write("./scionlab-config-user --url '%s'" % topo.coordinator.get_url())
    if force:
        cmd.write(" --force")
    run_in_matching_cntrs(topo, as_pattern, cmd.getvalue(), SCION_USER, detach)


def _run_in_cntr(
    cntr, cmd: str, user: str, detach: bool = False):
    """Run `cmd` in `cntr` and stream the command output to stdout.

    :param cntr: Docker container to run the command in.
    :param cmd: The command to run.
    :param user: User to run the command as.
    :param detach: If true, the command is detached from the Docker exec and no output is forwarded.
    """
    log.info("Running '{}' in {}.".format(cmd, cntr.name))
    try:
        _, stream = cntr.exec_run(cmd, user=user, stream=True, detach=detach)
        if not detach:
            for chunk in stream:
                print(chunk.decode('utf-8'), end='')
    except KeyboardInterrupt:
        sys.exit("Detached.")
