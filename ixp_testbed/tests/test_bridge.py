import ipaddress
import logging
import unittest

from ixp_testbed import errors
from ixp_testbed.address import IfId, ISD_AS, L4Port
from ixp_testbed.coordinator import Coordinator
from ixp_testbed.host import LocalHost
from ixp_testbed.network.docker import DockerBridge
from ixp_testbed.network.host import HostNetwork
from ixp_testbed.scion import AS
from ixp_testbed.util.typing import unwrap


class TestBridge(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)


    def test_ip_addr_assignment(self):
        br = DockerBridge("test", LocalHost(), ipaddress.IPv4Network("10.0.0.0/29"))
        asys = AS(LocalHost(), False)
        coord = Coordinator(LocalHost(), br)

        # Assign coordinator IP
        for _ in range(2): # Multiple calls must return the same address
            ip = br.assign_ip_address(coord)
            self.assertEqual(ip, ipaddress.IPv4Address(0x0A000002))

        # Assign AS IPs
        for asys in range(1, 5):
            ip = br.assign_ip_address((ISD_AS(asys), asys))
            self.assertEqual(ip, ipaddress.IPv4Address(0x0A000000 + asys + 2))

        with self.assertRaises(errors.OutOfResources):
            br.assign_ip_address((ISD_AS(8), asys))

        # Retrive assigned addresses
        self.assertEqual(br.get_ip_address(coord), ipaddress.IPv4Address(0x0A000002))
        for asys in range(1, 5):
            ip = br.get_ip_address(ISD_AS(asys))
            self.assertEqual(ip, ipaddress.IPv4Address(0x0A000000 + asys + 2))

        # Free and reassign an addresses
        ip = br.get_ip_address(ISD_AS(2))
        self.assertEqual(br.free_ip_address(ISD_AS(2)), 0)
        self.assertIsNone(br.get_ip_address(ISD_AS(2)))
        self.assertEqual(br.assign_ip_address((ISD_AS(6), asys)), ip)


    def test_br_addr_assignment(self):
        """Test assignment of (IP, port) tuples to border router interfaces."""
        br = DockerBridge("test", LocalHost(), ipaddress.IPv4Network("10.0.0.0/29"))
        asys = AS(LocalHost(), False)

        # Assign BR interface addresses
        for _ in range(2): # Multiple calls must return the same addresses
            for ifid in range(1, 3):
                for as_id in range(1, 6):
                    ip, port = br.assign_br_address(ISD_AS(as_id), asys, IfId(ifid))
                    self.assertEqual(ip, ipaddress.IPv4Address(0x0A000000 + as_id + 1))
                    self.assertEqual(port, 50000 + ifid - 1)

        with self.assertRaises(errors.OutOfResources):
            br.assign_br_address(ISD_AS(8), asys, IfId(1))

        # AS IP assignment
        for as_id in range(1, 6):
            isd_as = ISD_AS(as_id)
            self.assertEqual(br.get_ip_address(isd_as), br.assign_ip_address((isd_as, asys)))

        # Retrieve BR interface underlay addresses
        for ifid in range(1, 3):
            for asys in range(1, 6):
                ip, port = unwrap(br.get_br_address(ISD_AS(asys), IfId(ifid)))
                self.assertEqual(ip, ipaddress.IPv4Address(0x0A000000 + asys + 1))
                self.assertEqual(port, 50000 + ifid - 1)

        # Free BR interfaces
        for asys in range(1, 6):
            for ifid in range(1, 3):
                self.assertEqual(br.free_br_address(ISD_AS(asys), IfId(ifid)), 3 - ifid)

        # Check whether IPs are still bound
        for asys in range(1, 6):
            ip = br.get_ip_address(ISD_AS(asys))
            self.assertEqual(ip, ipaddress.IPv4Address(0x0A000000 + asys + 1))


class TestHostNetwork(unittest.TestCase):
    def test_addr_assignment(self):
        """Test correct assignment of Docker host addresses to border router interfaces."""
        net = HostNetwork("host_network", ipaddress.ip_network("10.0.0.0/24"))
        hosts = [LocalHost(), LocalHost()]
        asys = [AS(host, False) for host in hosts]

        net.set_host_ip(hosts[0], ipaddress.ip_address("10.0.0.10"))
        net.set_host_ip(hosts[1], ipaddress.ip_address("10.0.0.11"))

        with self.assertRaises(errors.NotAvailable):
            net.assign_br_address(ISD_AS("1-ff00:0:000"), asys[0], IfId(1),
            pref_ip=ipaddress.ip_address("10.0.0.2"))

        ip, port = net.assign_br_address(ISD_AS("1-ff00:0:000"), asys[0], IfId(1))
        self.assertEqual(ip, ipaddress.ip_address("10.0.0.10"))
        self.assertEqual(port, L4Port(50000))

        ip, port = net.assign_br_address(ISD_AS("1-ff00:0:001"), asys[1], IfId(1))
        self.assertEqual(ip, ipaddress.ip_address("10.0.0.11"))
        self.assertEqual(port, L4Port(50000))

        ip, port = net.assign_br_address(ISD_AS("1-ff00:0:001"), asys[1], IfId(2))
        self.assertEqual(ip, ipaddress.ip_address("10.0.0.11"))
        self.assertEqual(port, L4Port(50001))
