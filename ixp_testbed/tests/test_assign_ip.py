import ipaddress
import logging
import unittest

from lib.packet.scion_addr import ISD_AS
import yaml

from ixp_testbed import errors
from ixp_testbed.address import IfId, L4Port, UnderlayAddress
from ixp_testbed.gen.addr_alloc import assign_underlay_addresses, check_subnet_overlap
from ixp_testbed.gen.generator import extract_topo_info
from ixp_testbed.network.docker import DockerBridge
from ixp_testbed.network.ovs_bridge import OvsBridge


TEST_TOPO = """
defaults:
  subnet: "127.0.0.0/8"
  link_subnet: "10.0.10.0/24"
  zookeepers:
    1:
      addr: 127.0.0.1
networks:
  "ixp1":
    type: "ovs_bridge"
    subnet: "10.0.20.0/24"
  "ixp2":
    type: "overlay"
    subnet: "10.0.21.0/24"
ASes:
  "1-ff00:0:110":
    core: true
    mtu: 1400
  "1-ff00:0:111":
    cert_issuer: 1-ff00:0:110
  "1-ff00:0:112":
    cert_issuer: 1-ff00:0:110
  "1-ff00:0:113":
    cert_issuer: 1-ff00:0:110
IXPs:
  "ixp1":
    network: "ixp1"
  "ixp2":
    network: "ixp2"
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#1", linkAtoB: CHILD, mtu: 1280}
  - {a: "1-ff00:0:110#2", b: "1-ff00:0:112-name#1", linkAtoB: CHILD, bw: 500, network: "10.0.11.0/29"}
  - {a: "1-ff00:0:111#2", b: "1-ff00:0:112-name#2", linkAtoB: PEER, network: "ixp1"}
  - {a: "1-ff00:0:111#3", b: "1-ff00:0:113#1", linkAtoB: CHILD, network: "ixp1"}
  - {a: "1-ff00:0:112-name#3", b: "1-ff00:0:113#2", linkAtoB: CHILD, network: "ixp1"}
  - {a: "1-ff00:0:112", b: "1-ff00:0:113", linkAtoB: PEER, network: "ixp2"}
CAs:
  CA1-1:
    ISD: 1
    commonName: CA1-1
"""

class TestAssignIpAddresses(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        topo_file = yaml.load(TEST_TOPO)
        self.topo = extract_topo_info(topo_file)


    def tearDown(self):
        logging.disable(logging.NOTSET)


    def test(self):
        """Test successful address assignment."""
        topo = self.topo
        assign_underlay_addresses(topo)

        self.assertEqual(len(topo.bridges), 4)

        # link 1
        net = topo.get_bridge_subnet(ipaddress.ip_network("10.0.10.0/29"))
        self.assertIsInstance(net, DockerBridge)
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:110"), IfId(1)),
                         UnderlayAddress(ipaddress.ip_address("10.0.10.2"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:111"), IfId(1)),
                         UnderlayAddress(ipaddress.ip_address("10.0.10.3"), L4Port(50000)))

        # link 2
        net = topo.get_bridge_subnet(ipaddress.ip_network("10.0.11.0/29"))
        self.assertIsInstance(net, DockerBridge)
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:110"), IfId(2)),
                         UnderlayAddress(ipaddress.ip_address("10.0.11.2"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:112"), IfId(1)),
                         UnderlayAddress(ipaddress.ip_address("10.0.11.3"), L4Port(50000)))

        # links 3 to 5
        net = topo.get_bridge_subnet(ipaddress.ip_network("10.0.20.0/24"))
        self.assertIsInstance(net, OvsBridge)
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:111"), IfId(2)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.2"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:111"), IfId(3)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.2"), L4Port(50001)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:112"), IfId(2)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.3"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:112"), IfId(3)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.3"), L4Port(50001)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:113"), IfId(1)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.4"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:113"), IfId(2)),
                         UnderlayAddress(ipaddress.ip_address("10.0.20.4"), L4Port(50001)))

        # link 6
        net = topo.get_bridge_subnet(ipaddress.ip_network("10.0.21.0/24"))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:112"), IfId(4)),
                    UnderlayAddress(ipaddress.ip_address("10.0.21.9"), L4Port(50000)))
        self.assertEqual(net.get_br_address(ISD_AS("1-ff00:0:113"), IfId(3)),
                    UnderlayAddress(ipaddress.ip_address("10.0.21.10"), L4Port(50000)))

    def test_default_subnet_overlap(self):
        """Test overlapping subnets."""
        topo = self.topo
        topo.default_link_subnet = ipaddress.ip_network("10.0.20.64/26")
        with self.assertRaises(errors.SubnetOverlap):
            check_subnet_overlap(topo)


    def test_no_default_link_subnet(self):
        """Test missing default subnet when not all link subnets are specified."""
        topo = self.topo
        topo.default_link_subnet = None
        with self.assertRaises(errors.OutOfResources):
            assign_underlay_addresses(topo)


    def test_invalid_subnet(self):
        """Test an invalid link subnet."""
        topo_file = yaml.load(TEST_TOPO)
        self.topo = extract_topo_info(topo_file)
        topo_file['links'][1]['network'] = "10.0.11.0/30"
        topo = extract_topo_info(topo_file)
        with self.assertRaises(errors.OutOfResources):
            assign_underlay_addresses(topo)
