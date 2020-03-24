import ipaddress
import logging
import unittest

from lib.packet.scion_addr import ISD_AS
import yaml

from ixp_testbed.address import IfId
from ixp_testbed.gen.generator import extract_topo_info
from ixp_testbed.network.docker import DockerBridge
from ixp_testbed.network.ovs_bridge import OvsBridge
from ixp_testbed.scion import LinkEp


TEST_TOPO = """
defaults:
  subnet: "127.0.0.0/8"
  link_subnet: "10.0.10.0/24"
  zookeepers:
    1:
      addr: 127.0.0.1
networks:
  "ixp_network":
    type: "ovs_bridge"
    subnet: "10.0.20.0/24"
ASes:
  "1-ff00:0:110":
    core: true
    mtu: 1400
  "1-ff00:0:111":
    cert_issuer: 1-ff00:0:110
  "1-ff00:0:112":
    cert_issuer: 1-ff00:0:110
IXPs:
  "ixp1":
    network: "ixp_network"
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#1", linkAtoB: CHILD, mtu: 1280}
  - {a: "1-ff00:0:110#2", b: "1-ff00:0:112-name#1", linkAtoB: CHILD, bw: 500, network: "10.0.11.0/29"}
  - {a: "1-ff00:0:111#2", b: "1-ff00:0:112-name#2", linkAtoB: PEER, network: "ixp1"}
CAs:
  CA1-1:
    ISD: 1
    commonName: CA1-1
"""

class TestExtractTopoInfo(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)


    def tearDown(self):
        logging.disable(logging.NOTSET)


    def test(self):
        """Test successful parse."""
        topo_file = yaml.load(TEST_TOPO)
        topo = extract_topo_info(topo_file)
        ASES = [ISD_AS("1-ff00:0:110"), ISD_AS("1-ff00:0:111"), ISD_AS("1-ff00:0:112")]

        # IPv6
        self.assertFalse(topo.ipv6_enabled)

        # Default link subnet
        self.assertEqual(topo.default_link_subnet, ipaddress.ip_network("10.0.10.0/24"))

        # ASes
        self.assertEqual(len(topo.ases), 3)
        for asys in ASES:
            self.assertIn(asys, topo.ases)

        # IXPs
        self.assertIn("ixp1", topo.ixps)
        ixp = topo.ixps["ixp1"]
        for isd_as in [ISD_AS("1-ff00:0:111"), ISD_AS("1-ff00:0:112")]:
            self.assertIn(isd_as, ixp.ases)
            self.assertIs(ixp.ases[isd_as], topo.ases[isd_as])

        # Networks
        self.assertEqual(len(topo.bridges), 2)
        ip_net = ipaddress.ip_network("10.0.11.0/29")
        self.assertIsInstance(topo.get_bridge_subnet(ip_net), DockerBridge)
        ip_net = ipaddress.ip_network("10.0.20.0/24")
        self.assertIsInstance(topo.get_bridge_subnet(ip_net), OvsBridge)

        # Links
        self.assertEqual(len(topo.links), 3)
        self.assertEqual(topo.links[0].ep_a, LinkEp("1-ff00:0:110#1"))
        self.assertEqual(topo.links[0].ep_b, LinkEp("1-ff00:0:111#1"))
        self.assertIsNone(topo.links[0].bridge)
        self.assertEqual(topo.links[1].ep_a, LinkEp("1-ff00:0:110#2"))
        self.assertEqual(topo.links[1].ep_b, LinkEp("1-ff00:0:112#1"))
        self.assertEqual(topo.links[1].bridge, topo.get_bridge_subnet(ipaddress.ip_network("10.0.11.0/29")))
        self.assertEqual(topo.links[2].ep_a, LinkEp("1-ff00:0:111#2"))
        self.assertEqual(topo.links[2].ep_b, LinkEp("1-ff00:0:112#2"))
        self.assertEqual(topo.links[2].bridge, topo.get_bridge_subnet(ipaddress.ip_network("10.0.20.0/24")))

        # BRs
        self.assertEqual(len(topo.ases[ASES[0]].border_routers), 2)
        self.assertEqual(len(topo.ases[ASES[1]].border_routers), 2)
        self.assertEqual(len(topo.ases[ASES[2]].border_routers), 1)

        # br1-ff00_0_110-1
        br = topo.ases[ASES[0]].border_routers[0]
        self.assertEqual(br.id, 1)
        self.assertEqual(br.get_name(ASES[0]), "br1-ff00_0_110-1")
        self.assertEqual(len(br.links), 1)
        self.assertIs(br.links[IfId(1)], topo.links[0])

        # br1-ff00_0_110-2
        br = topo.ases[ASES[0]].border_routers[1]
        self.assertEqual(br.id, 2)
        self.assertEqual(br.get_name(ASES[0]), "br1-ff00_0_110-2")
        self.assertEqual(len(br.links), 1)
        self.assertIs(br.links[IfId(2)], topo.links[1])

        # br1-ff00_0_111-1
        br = topo.ases[ASES[1]].border_routers[0]
        self.assertEqual(br.id, 1)
        self.assertEqual(br.get_name(ASES[1]), "br1-ff00_0_111-1")
        self.assertEqual(len(br.links), 1)
        self.assertIs(br.links[IfId(1)], topo.links[0])

        # br1-ff00_0_111-2
        br = topo.ases[ASES[1]].border_routers[1]
        self.assertEqual(br.id, 2)
        self.assertEqual(br.get_name(ASES[1]), "br1-ff00_0_111-2")
        self.assertEqual(len(br.links), 1)
        self.assertIs(br.links[IfId(2)], topo.links[2])

        # br1-ff00_0_112-1
        br = topo.ases[ASES[2]].border_routers[0]
        self.assertEqual(br.id, 1)
        self.assertEqual(br.get_name(ASES[2]), "br1-ff00_0_112-1")
        self.assertEqual(len(br.links), 2)
        self.assertIs(br.links[IfId(1)], topo.links[1])
        self.assertIs(br.links[IfId(2)], topo.links[2])

        # topo_file
        self.assertNotIn("link_subnet", topo_file['defaults'])
        self.assertNotIn("IXPs", topo_file)
        for link in topo_file['links']:
            self.assertNotIn('network', link)


    def test_ipv6(self):
        """Test detection of IPv6 addresses."""
        topo_file = yaml.load(TEST_TOPO)
        topo_file['networks']['ixp_network']['subnet'] = "fd00:72c2:d7f1:ff01::/64"

        topo = extract_topo_info(topo_file)
        self.assertTrue(topo.ipv6_enabled)


    def test_no_ifid(self):
        """Test `extract_topo_info` with a link missing an interface identifier."""
        topo_file = yaml.load(TEST_TOPO)
        topo_file['links'][0]['a'] = "1-ff00:0:110-test"

        extract_topo_info(topo_file)
        self.assertEqual(topo_file['links'][0]['a'], "1-ff00:0:110-test#1")
