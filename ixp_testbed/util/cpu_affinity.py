"""Helpers form managing the CPU affinity of containers."""

from typing import Set, Union, Optional, List


class CpuSet:
    """An (immutable) set of CPUs.

    :ivar _cpu_set: Sorted list of zero-based CPU indices.
                    If None, all CPUs are considered part of the set.
    """

    def __init__(self, cpu_set: Union[Set[int], str, None] = None):
        """Construct a CPU set from `cpu_set`.

        :param cpu_set: If None, the set contains all CPUs available on any given system.
                        Strings get parsed by _parse_cpu_set(). Sets of (non-negative) integers are
                        interpreted as CPU indices.
        """
        if isinstance(cpu_set, set):
            self._cpu_set: Optional[List[int]] = sorted(cpu_set)
        elif isinstance(cpu_set, str):
            self._cpu_set: Optional[List[int]] = _parse_cpu_set(cpu_set)
        else:
            self._cpu_set = None

    def is_unrestricted(self) -> bool:
        """Returns true if all availabile CPUs should be considered part of the set."""
        return self._cpu_set is None

    def __str__(self):
        """Returns a string representation suitable for setting CPU affinity in Docker.
        If the set is not restricted at all, an empty string is returned.
        """
        if self._cpu_set is not None:
            return ",".join(str(cpu) for cpu in self._cpu_set)
        else:
            return ""


def _parse_cpu_set(cpu_list: str) -> List[int]:
    """Parse a set of comma separeted CPU index. Ranges of CPUs are specified by the first and last
    CPU in the range separated by a hyphen.

    Example: '0,1,4-6,8-10' uses CPUs 0, 1, 4, 5, 6, 8, 9, 10

    :returns: An ordered list of CPU indices.
    """
    result = set()

    for list_elem in cpu_list.split(','):
        split = list_elem.split('-')
        if len(split) == 1:
            result.add(int(split[0]))
        elif len(split) == 2:
            start, end = int(split[0]), int(split[1])
            for cpu in range(start, end + 1):
                result.add(cpu)
        else:
            raise ValueError("Invalid CPU set")

    return sorted(result)
