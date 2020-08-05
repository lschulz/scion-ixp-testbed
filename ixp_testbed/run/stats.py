"""Performance measurement tools."""

from datetime import datetime, timezone
import logging
import re
import time
from typing import Dict, List, MutableMapping, Set

import docker

from ixp_testbed.address import ISD_AS
from ixp_testbed.scion import AS
from ixp_testbed.topology import Topology

log = logging.getLogger(__name__)


class Measurements:
    """Records timestamped performance metrics sorted by experiment, AS, and process."""
    def __init__(self):
        self.data: Dict = {}
        self.experiment = "default"
        self.as_id = "undefined"

    def add_values(self, process: str, timestamp: float, cpu_time: float):
        """Add a measurement values for the given process.

        The AS and experiment the new values belong to are controlled by `self.as_id` and
        `self.experiment`.

        :param process: The process the measurements belong to. Use 'total' for the container totals.
        :param timestamp: Unix timestamp of the measurement (in seconds).
        :param cpu_time: Total elapsed CPU time of the process/process group (in seconds).
        """
        as_data = self.data.setdefault(self.as_id, {})
        process_data = as_data.setdefault(process, {})
        timeseries = process_data.setdefault(self.experiment, {})

        if len(timeseries) == 0:
            timeseries['timestamp'] = []
            timeseries['cpu_time'] = []

        timeseries['timestamp'].append(timestamp)
        timeseries['cpu_time'].append(cpu_time)


def measure_perf_stats(topo: Topology, measurements: Measurements,
    as_pattern: str = ".*", services: Set[str] = set(),
    interval: float = 10.0, count: int = 2) -> None:
    """Record the CPU time of AS processes in containers.

    CPU time is measured for all processes in the matching containers in total
    and for processes selected by the `services` parameter individually.

    :param measurements: Set of measurements to add the new data to.
    :param as_pattern: Regular expression matched against ISD-AS strings. Measurements are taken in
                       matching ASes only.
    :param services: Set of strings identifying SCION service executables, like "bin/border",
                     and "bin/cs".
    :param interval: Time interval to take measurements over.
    :param count: The number of measurements to take.
    """
    # Get ASes matching the pattern
    ases = []
    try:
        regex = re.compile(as_pattern)
    except re.error:
        print("Invalid regular expression: '{}'".format(as_pattern))
        return
    for isd_as, _ in topo.ases.items():
        if regex.fullmatch(str(isd_as)):
            ases.append(isd_as)

    # Get pids of processes matching the selection criteria
    process_map: Dict[ISD_AS, Dict[int, str]] = {}
    for isd_as in ases:
        process_map[isd_as] = _get_pid_map(isd_as, topo.ases[isd_as], services)

    # Take the measurements
    for i in range(count):
        for isd_as in ases:
            measurements.as_id = isd_as.as_str()
            data = _get_current_values(isd_as, topo.ases[isd_as], process_map[isd_as])
            for process, values in data.items():
                measurements.add_values(process, **values)
        if i < count - 1:
            time.sleep(interval)


def _get_pids(isd_as: ISD_AS, asys: AS) -> List[str]:
    """Get a list of all process ids in the given AS."""

    cmd = ["cat", "/sys/fs/cgroup/pids/docker/%s/cgroup.procs" % asys.container_id]
    result = asys.host.run_cmd(cmd, check=True, capture_output=True)

    return [pid for pid in result.output.splitlines()]


def _get_pid_map(isd_as: ISD_AS, asys: AS, executables: Set[str]) -> Dict[int, str]:
    """Get a mapping from commands running in the given AS container to process ids on the host.

    :param executables: Set of executables to include in the map.
    """
    pid_map = {}
    if len(executables) == 0:
        return pid_map

    pids = _get_pids(isd_as, asys)

    cmd = ["ps", "-o", "pid,command", "--no-header", *pids]
    result = asys.host.run_cmd(cmd, check=True, capture_output=True)

    for line in result.output.splitlines():
        pid, executable, *args = line.split()
        if executable in executables:
            pid_map[int(pid)] = " ".join([executable, *args])

    return pid_map


def _get_current_values(isd_as: ISD_AS, asys: AS, processes: MutableMapping[int, str]
    ) -> Dict[str, Dict[str, float]]:
    """Get the current timer values in the given AS.

    :param pids: Set of processes (identified by PID) for which to grab elapsed CPU time.
                 If a process does not exist anymore, it is removed from the mapping.
    """
    cmd = ["cat", "/sys/fs/cgroup/cpu/docker/%s/cpuacct.usage" % asys.container_id]
    pids = list(processes.keys())
    cmd.extend("/proc/%s/stat" % pid for pid in pids)

    result = asys.host.run_cmd(cmd, capture_output=True)
    if (result.exit_code != 0):
        log.warning("Non-zero exit code from cat:\n%s", result.output)

    lines = result.output.splitlines()
    if lines[0].startswith("cat"):
        log.critical("Container of AS %s is gone." % isd_as)
        exit(1)

    # Parse total container CPU time
    timestamp = datetime.now(timezone.utc).timestamp()
    values = {'total': {
        'timestamp': timestamp,
        'cpu_time': 1e-9 * float(lines[0]) # original value is in nanoseconds
    }}

    # Parse per process CPU time
    for pid, line in zip(pids, lines[1:]):
        if not line.startswith("cat"):
            fields = line.split()
            assert pid == int(fields[0])
            values[processes[pid]] = {
                'timestamp': timestamp,
                'cpu_time': 1e-2 * (float(fields[13]) + float(fields[14])) # original value in jiffies
            }
        else:
            log.warning("Process '%s' (%d) is gone.", processes[pid], pid)
            del processes[pid]

    return values
