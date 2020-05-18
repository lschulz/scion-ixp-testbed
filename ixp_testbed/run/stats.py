"""Performance measurement tools."""

import re
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Set

import docker

from ixp_testbed.scion import AS
from ixp_testbed.address import ISD_AS
from ixp_testbed.topology import Topology


def measure_perf_stats(topo: Topology,
    as_pattern: str = ".*", services: Set[str] = set(),
    interval: float = 60.0, count: int = 1):
    """Measure the average CPU utilization in AS containers.

    CPU utilization is measured for all processes in the matching containers in total
    and for processes selected by the `services` parameter individually.

    :param as_pattern: Regular expression matched against ISD-AS strings. Measurements are taken in
                       matching ASes only.
    :param services: Set of strings identifying SCION service executables, like "bin/border",
                     "bin/beacon_srv", and "bin/path_srv".
    :param interval: Time interval to take measurements over.
    :param count: The number of measurements to take.
    :returns: Dictionary containing the measured CPU utilizations.
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

    # Prepare dictionary to hold the results
    measurements = {str(isd_as): {'cpu': [], 'processes': defaultdict(list)} for isd_as in ases}

    # Take the measurements
    # Get current wall-clock time and CPU time
    values_t0 = []
    for isd_as in ases:
        values_t0.append(
            _get_current_values(isd_as, topo.ases[isd_as], process_map[isd_as].keys()))

    for _ in range(count):
        # Wait
        time.sleep(interval)

        # Get current wall-clock time and CPU time
        values_t1 = []
        for isd_as in ases:
            values_t1.append(
                _get_current_values(isd_as, topo.ases[isd_as], process_map[isd_as].keys()))

        # Calculate deltas and CPU utilization
        for isd_as, t0, t1 in zip(ases, values_t0, values_t1):
            delta = t1 - t0
            m = measurements[str(isd_as)]
            m['cpu'].append(delta.total_cpu_time / delta.wall_clock_time)
            for pid, cpu_time in delta.processes.items():
                command = process_map[isd_as][pid]
                m['processes'][command].append(cpu_time / delta.wall_clock_time)

        # Take measurements back-to-back
        values_t0 = values_t1
        values_t1 = None

    return measurements


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


class _TimerValues:
    """Holds timer values obtained from AS containers.

    :ivar wall_clock_time: Wall-clock time elapsed in the container.
    :ivar total_cpu_time: Total CPU time consumed by the container.
    :ivar processes: Map from process id to cpu time consumed by that process.
    """
    def __init__(self, wall_clock_time, total_cpu_time, processes):
        self.wall_clock_time: float = wall_clock_time
        self.total_cpu_time: float = total_cpu_time
        self.processes: Dict[int, float] = processes

    def __sub__(self, other):
        """Calculate elapsed time between two timepoints.

        Elapsed time is calculated for all pids with a value in both `self` and `other`.
        """
        wall_clock_time = other.wall_clock_time - self.wall_clock_time
        total_cpu_time = other.total_cpu_time - self.total_cpu_time

        processes = {}
        for pid, cpu_time in self.processes.items():
            if pid in other.processes:
                processes[pid] = other.processes[pid] - cpu_time

        return _TimerValues(wall_clock_time, total_cpu_time, processes)


def _get_current_values(isd_as: ISD_AS, asys: AS, pids: Iterable[int]) -> _TimerValues:
    """Get the current timer values in the given AS.

    :param pids: Set of processes (identified by PID) for which to grab elapsed CPU time.
    """
    cmd = ["cat", "/proc/uptime",
           "/sys/fs/cgroup/cpu/docker/%s/cpuacct.usage" % asys.container_id]
    cmd.extend("/proc/%s/stat" % pid for pid in pids)
    result = asys.host.run_cmd(cmd, check=True, capture_output=True)

    lines = result.output.splitlines()
    timestamp = float(lines[0].split()[0])  # original value is in seconds (10 ms resolution)
    total_cpu_time = 1e-9 * float(lines[1]) # original value is in nanoseconds

    processes = {}
    for line in lines[2:]:
        fields = line.split()
        pid = int(fields[0])
        cpu_time = 1e-2 * (float(fields[13]) + float(fields[14])) # original value in jiffies
        processes[pid] = cpu_time

    return _TimerValues(timestamp, total_cpu_time, processes)
