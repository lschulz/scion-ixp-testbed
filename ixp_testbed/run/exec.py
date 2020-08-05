"""Functions for executing commands in AS containers."""

import io
import logging
import re
import sys
import time
from typing import Iterable, List, Mapping, Optional, Tuple, Union

import docker

from ixp_testbed.constants import SCION_USER
from ixp_testbed.scion import AS, ISD_AS
from ixp_testbed.topology import Topology

log = logging.getLogger(__name__)


def run_in_cntrs(
    topo: Topology, as_selector: Union[str, List[ISD_AS]],
    cmd_template: str, user: str, detach: bool = False, dry_run: bool = False,
    rate: Optional[float] = None):
    """Run a command in all AS containers identified by `as_selector`.

    :param topo: Topology database.
    :param as_selector: Either a regular expression to match against ISD-AS strings like
                        '1-ff00:0:110', or a list of ISD-AS ids. If a regular expressing is given,
                        the command is executed in all ases whose ISD-AS string matches the pattern.
                        If a list is given, the command is executed in all ASes on the list, in the
                        order given by the list.
    :param cmd_template: Command to execute. The template is formated using str.format() for each AS.
                         Availabile variables are: 'isd_as', 'file_fmt'
    :param user: User to run the command as.
    :param detach: If true, the command is detached from the Docker exec and no output is forwarded.
    :param dry_run: If true, the command is not actually executed, just printed to stdout.
    :param rate: If not None, the rate with which the command is given to ASes is limited to `rate`
                 ASes per minute.
    """
    if isinstance(as_selector, str):
        try:
            regex = re.compile(as_selector)
        except re.error:
            print("Invalid regular expression: '{}'".format(as_selector))
        else:
            ases = _get_ases_regex(topo.ases, regex)
            _run_in_cntrs(topo, ases, cmd_template, user, detach, dry_run, rate)

    elif isinstance(as_selector, list):
        ases = _get_ases_list(topo.ases, as_selector)
        _run_in_cntrs(topo, ases, cmd_template, user, detach, dry_run, rate)

    else:
        raise TypeError("Invalid type for 'as_selector'.")


def fetch_config(topo: Topology, as_selector: Union[str, List[ISD_AS]] = '.*', *,
    detach: bool = True, force: bool = False, no_restart: bool = False,
    rate: Optional[float] = None):
    """Fetch the most recent configuration from the coordinator.

    :param topo: A topology containing a coordinator.
    :param as_selector: If a regular expression, all ASes matching the pattern are updated.
                        If a list of ISD-AS ids, ASes on the list are updated in the order given by
                        the list.
    :param detach: If set to true, the program does not wait for the containers complete the
                   configuration update and no command output is printed to stdout.
    :param force: If true, the configuration is downloaded from the coordinator and installed, even
                  when the currently installed configuration should be up to date.
    :param no_restart: Do not restart the AS after installing a new configuration.
    :param rate: Limit the rate with which ASes are updated to `rate` ASes per minute.
    """
    cmd = io.StringIO()
    cmd.write("./scionlab-config-user --url '%s'" % topo.coordinator.get_url())
    if force:
        cmd.write(" --force")
    if no_restart:
        cmd.write(" --no-restart")
    run_in_cntrs(topo, as_selector, cmd.getvalue(), SCION_USER, detach, rate=rate)


def _get_ases_list(ases: Mapping[ISD_AS, AS], as_list: List[ISD_AS]):
    """Generator returning ASes from a list."""
    for isd_as in as_list:
        asys = ases.get(isd_as)
        if asys is None:
            log.warning("No AS %s.", isd_as)
            continue
        yield isd_as, asys


def _get_ases_regex(ases: Mapping[ISD_AS, AS], as_regex):
    """Generator returning ASes matching a regular expression."""
    for isd_as, asys in ases.items():
        if as_regex.fullmatch(str(isd_as)):
            yield isd_as, asys


def _run_in_cntrs(
    topo: Topology, ases: Iterable[Tuple[ISD_AS, AS]],
    cmd_template: str, user: str, detach: bool = False, dry_run: bool = False,
    rate: Optional[float] = None):
    """Run a command in many AS containers, optionally limiting the rate."""
    if rate is None:
        for isd_as, asys in ases:
            _format_and_run(topo, isd_as, asys, cmd_template, user, detach, dry_run)

    else:
        delay = 60 / rate
        max_delay = 0

        as_count = 0
        t_total_0 = time.time()
        for isd_as, asys in ases:
            as_count += 1
            t0 = time.time()
            _format_and_run(topo, isd_as, asys, cmd_template, user, detach, dry_run)
            t1 = time.time()
            elapsed = t1 - t0

            if elapsed < delay:
                time.sleep(delay - elapsed)
            max_delay = max(max_delay, time.time() - t0)

        t_total_1 = time.time()
        elapsed_total = (t_total_1 - t_total_0) / 60
        avg_rate = as_count / elapsed_total
        min_rate = 60 / max_delay
        log.info("Ran command in {} container(s). Average rate: {:.2f} cntrs/min."
                 " Minimum rate: {:.2f} cntrs/min.".format(as_count, avg_rate, min_rate))
        if elapsed_total > (as_count * delay + 1) or max_delay > delay + 1:
            log.warning("Rate was lower than requested.")


def _format_and_run(
    topo: Topology, isd_as: ISD_AS, asys: AS, cmd_template: str,
    user: str, detach:bool, dry_run: bool):
    """Format the given command template and run the command in the given AS."""
    if not asys.container_id:
        print("No container for AS{}.".format(isd_as))
    else:
        try:
            cntr = asys.get_container()
        except docker.errors.NotFound:
            cntr_name = topo.get_cntr_name(isd_as)
            log.warning("Container {} ({}) not found.".format(cntr_name, asys.container_id))
        else:
            cmd = cmd_template.format(isd_as=str(isd_as), file_fmt=isd_as.file_fmt())
            if dry_run:
                print("Would run '{}' in {}.".format(cmd, cntr.name))
            else:
                _run_in_cntr(cntr, cmd, user, detach)


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
