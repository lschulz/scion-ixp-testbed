"""Helpers for dealing with border router interface IDs."""

from typing import List

from ixp_testbed.address import IfId
from ixp_testbed.constants import FIRST_IFID


def pick_unused_ifid(ifids: List[IfId]) -> IfId:
    """Returns the smallest interface ID not in `ifids`.

    :param ifids: List of ifids in ascending order.
    """
    if len(ifids) == 0:
        return IfId(FIRST_IFID)
    else:

        for i, ifid in enumerate(ifids):
            if (i + FIRST_IFID) != ifid:
                return IfId(i + FIRST_IFID)
        else:
            return IfId(ifids[-1] + 1)
