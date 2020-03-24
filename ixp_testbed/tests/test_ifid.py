import unittest

from lib.types import LinkType

from ixp_testbed.address import IfId
from ixp_testbed.host import LocalHost
from ixp_testbed.scion import AS, BorderRouter, Link, LinkEp


class testAS(unittest.TestCase):
    def setUp(self):
        asys = AS(LocalHost(), True)
        asys.border_routers = [
            BorderRouter(1),
            BorderRouter(2)
        ]
        asys.border_routers[0].links[IfId(2)] = Link(LinkEp("1-ff00:0:110-br1#2"), LinkEp("2-ff00:0:210#1"), LinkType.CORE)
        asys.border_routers[0].links[IfId(4)] = Link(LinkEp("1-ff00:0:110-br1#4"), LinkEp("2-ff00:0:211#1"), LinkType.CORE)
        asys.border_routers[1].links[IfId(5)] = Link(LinkEp("1-ff00:0:110-br2#5"), LinkEp("1-ff00:0:111#1"), LinkType.CHILD)
        self.asys = asys


    def test_ifid_assignment(self):
        self.assertEqual(self.asys.get_unused_ifid(), 1)
        self.asys.border_routers[1].links[IfId(1)] = Link(
            LinkEp("1-ff00:0:110-br2#1"), LinkEp("1-ff00:0:112#1"), LinkType.CHILD)

        self.assertEqual(self.asys.get_unused_ifid(), 3)
        self.asys.border_routers[1].links[IfId(3)] = Link(
            LinkEp("1-ff00:0:110-br2#1"), LinkEp("1-ff00:0:113#1"), LinkType.CHILD)

        self.assertEqual(self.asys.get_unused_ifid(), 6)
