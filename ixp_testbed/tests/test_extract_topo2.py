import ipaddress
import logging
from typing import cast
import unittest

from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
import yaml

from ixp_testbed import errors
from ixp_testbed.address import IfId, L4Port, UnderlayAddress
from ixp_testbed.coordinator import User
from ixp_testbed.gen.addr_alloc import assign_underlay_addresses
from ixp_testbed.gen.generator import extract_topo_info
from ixp_testbed.host import LocalHost, RemoteHost
from ixp_testbed.network.docker import OverlayNetwork
from ixp_testbed.network.docker import DockerBridge
from ixp_testbed.network.host import HostNetwork
from ixp_testbed.network.ovs_bridge import OvsBridge
from ixp_testbed.scion import LinkEp


TEST_TOPO = """
defaults:
  subnet: "127.0.0.0/8"
  link_subnet: "10.0.10.0/24"
  zookeepers:
    1:
      addr: 127.0.0.1
hosts:
  "localhost":
    addresses: {
      "physical_network1" : "10.0.23.1"
    }
  "host1":
    ssh_host: "192.168.244.3"
    username: "scion"
    identity_file: ".ssh/id_rsa"
    addresses: {
      "physical_network1": "10.0.23.2"
    }
networks:
  "bridge1":
    type: "docker_bridge"
    subnet: "10.0.20.0/24"
    host: "localhost"
  "ovs_bridge1":
    type: "ovs_bridge"
    subnet: "10.0.21.0/24"
    host: "localhost"
  "overlay_bridge1":
    type: "overlay"
    subnet: "10.0.22.0/24"
    host: "host1"
    encrypted: true
  "physical_network1":
    type: "host"
    subnet: "10.0.23.0/24"
coordinator:
  network: "overlay_bridge1"
  host: "localhost"
  expose: "8000"
  expose_on: "192.168.244.2"
  users:
    "admin":
      email: "admin@example.com"
      password: "admin"
      superuser: true
    "user1":
      email: "user1@example.com"
      password: "user1"
    "user2":
      email: user2@example.com
      password: "user2"
ASes:
  "1-ff00:0:110":
    core: true
    host: "localhost"
  "1-ff00:0:111":
    cert_issuer: 1-ff00:0:110
    attachment_point: true
  "1-ff00:0:112":
    cert_issuer: 1-ff00:0:110
    owner: "user1"
    ixps: ["ixp1", "ixp2"]
  "1-ff00:0:113":
    cert_issuer: 1-ff00:0:110
    owner: "user1"
    ixps: ["ixp1", "ixp2"]
  "2-ff00:0:210":
    core: true
  "2-ff00:0:211":
    cert_issuer: 2-ff00:0:210
    attachment_point: true
  "2-ff00:0:212":
    cert_issuer: 2-ff00:0:210
    owner: "user2"
    host: "host1"
    ixps: ["ixp2"]
  "2-ff00:0:213":
    cert_issuer: 2-ff00:0:210
    owner: "user2"
    host: "host1"
    ixps: ["ixp2"]
IXPs:
  "ixp1":
    network: "10.0.12.0/24"
  "ixp2":
    network: "physical_network1"
links:
  - {a: "1-ff00:0:110-br1#1", b: "2-ff00:0:210-br1", linkAtoB: CORE, network: "10.0.13.0/24"}
  - {a: "1-ff00:0:110-br1", b: "1-ff00:0:111-br1", linkAtoB: CHILD, network: "10.0.13.0/24"}
  - {a: "2-ff00:0:210-br1", b: "2-ff00:0:211-br1", linkAtoB: CHILD, network: "10.0.13.0/24"}
  - {a: "1-ff00:0:111-user#1", b: "1-ff00:0:112", linkAtoB: CHILD}
  - {a: "1-ff00:0:111-user#2", b: "1-ff00:0:113", linkAtoB: CHILD}
  - {a: "2-ff00:0:211-user#1", b: "2-ff00:0:212", linkAtoB: CHILD, network: "overlay_bridge1"}
  - {a: "2-ff00:0:211-user#2", b: "2-ff00:0:213", linkAtoB: CHILD, network: "overlay_bridge1"}
"""

class TestExtractTopoInfo(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)


    def tearDown(self):
        logging.disable(logging.NOTSET)


    def test(self):
        """Test successful parse of a topology with multiple hosts and a coordinator."""
        topo_file = yaml.load(TEST_TOPO)
        topo = extract_topo_info(topo_file)
        assign_underlay_addresses(topo)

        # IPv6
        self.assertFalse(topo.ipv6_enabled)

        # Default link subnet
        self.assertEqual(topo.default_link_subnet, ipaddress.ip_network("10.0.10.0/24"))

        # Hosts
        self.assertEqual(len(topo.hosts), 2)
        self.assertIsInstance(topo.hosts['localhost'], LocalHost)
        self.assertIsInstance(topo.hosts['host1'], RemoteHost)

        host = cast(RemoteHost, topo.hosts['host1'])
        self.assertEqual(host.name, 'host1')
        self.assertEqual(host.ssh_host, ipaddress.ip_address("192.168.244.3"))
        self.assertEqual(host._ssh_port, 22)
        self.assertEqual(host._username, "scion")
        self.assertEqual(host._identity_file, ".ssh/id_rsa")

        # Networks
        self.assertEqual(len(topo.bridges), 8)

        bridge = topo.get_bridge_subnet(ipaddress.ip_network("10.0.20.0/24"))
        self.assertIsInstance(bridge, DockerBridge)
        self.assertEqual(bridge.name, "bridge1")
        self.assertEqual(cast(DockerBridge, bridge)._host, topo.hosts['localhost'])

        bridge = topo.get_bridge_subnet(ipaddress.ip_network("10.0.21.0/24"))
        self.assertIsInstance(bridge, OvsBridge)
        self.assertEqual(bridge.name, "ovs_bridge1")
        self.assertEqual(cast(OvsBridge, bridge)._host, topo.hosts['localhost'])

        bridge = topo.get_bridge_subnet(ipaddress.ip_network("10.0.22.0/24"))
        self.assertIsInstance(bridge, OverlayNetwork)
        self.assertEqual(bridge.name, "overlay_bridge1")
        self.assertEqual(cast(OverlayNetwork, bridge)._host, topo.hosts['host1'])
        self.assertEqual(cast(OverlayNetwork, bridge).encrypted, True)
        bridge = topo.get_bridge_subnet(ipaddress.ip_network("10.0.23.0/24"))

        self.assertIsInstance(bridge, HostNetwork)
        self.assertEqual(bridge.name, "physical_network1")

        # Coordinator
        self.assertIs(topo.coordinator.bridge, topo.get_bridge_name("overlay_bridge1"))
        self.assertIs(topo.coordinator.host, topo.hosts['localhost'])
        expected = UnderlayAddress(ipaddress.ip_address("192.168.244.2"), L4Port(8000))
        self.assertEqual(topo.coordinator.exposed_at, expected)

        self.assertEqual(len(topo.coordinator.users), 3)

        user = topo.coordinator.users['admin']
        self.assertEqual(user.email, "admin@example.com")
        self.assertEqual(user.password, "admin")
        self.assertTrue(user.is_admin)

        user = topo.coordinator.users['user1']
        self.assertEqual(user.email, "user1@example.com")
        self.assertEqual(user.password, "user1")
        self.assertFalse(user.is_admin)

        user = topo.coordinator.users['user2']
        self.assertEqual(user.email, "user2@example.com")
        self.assertEqual(user.password, "user2")
        self.assertFalse(user.is_admin)

        # ASes
        self.assertEqual(len(topo.ases), 8)

        asys = topo.ases[ISD_AS("1-ff00:0:110")]
        self.assertTrue(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertIsNone(asys.owner)

        asys = topo.ases[ISD_AS("1-ff00:0:111")]
        self.assertFalse(asys.is_core)
        self.assertTrue(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertIsNone(asys.owner)

        asys = topo.ases[ISD_AS("1-ff00:0:112")]
        self.assertFalse(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertEqual(asys.owner, "user1")

        asys = topo.ases[ISD_AS("1-ff00:0:113")]
        self.assertFalse(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertEqual(asys.owner, "user1")

        asys = topo.ases[ISD_AS("2-ff00:0:210")]
        self.assertTrue(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertIsNone(asys.owner)

        asys = topo.ases[ISD_AS("2-ff00:0:211")]
        self.assertFalse(asys.is_core)
        self.assertTrue(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['localhost'])
        self.assertIsNone(asys.owner)

        asys = topo.ases[ISD_AS("2-ff00:0:212")]
        self.assertFalse(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['host1'])
        self.assertEqual(asys.owner, "user2")

        asys = topo.ases[ISD_AS("2-ff00:0:213")]
        self.assertFalse(asys.is_core)
        self.assertFalse(asys.is_attachment_point)
        self.assertIs(asys.host, topo.hosts['host1'])
        self.assertEqual(asys.owner, "user2")

        # IXPs
        self.assertIn("ixp1", topo.ixps)
        ixp = topo.ixps["ixp1"]
        expected_ases = [
            ISD_AS("1-ff00:0:112"), ISD_AS("1-ff00:0:113")
        ]
        for isd_as in expected_ases:
            self.assertIn(isd_as, ixp.ases)
            self.assertIs(ixp.ases[isd_as], topo.ases[isd_as])
        self.assertIsInstance(ixp.bridge, DockerBridge)
        self.assertEqual(ixp.bridge.ip_network, ipaddress.ip_network("10.0.12.0/24"))

        self.assertIn("ixp2", topo.ixps)
        ixp = topo.ixps["ixp2"]
        expected_ases = [
            ISD_AS("1-ff00:0:112"), ISD_AS("1-ff00:0:113"),
            ISD_AS("2-ff00:0:212"), ISD_AS("2-ff00:0:213")
        ]
        for isd_as in expected_ases:
            self.assertIn(isd_as, ixp.ases)
            self.assertIs(ixp.ases[isd_as], topo.ases[isd_as])
        self.assertIsInstance(ixp.bridge, HostNetwork)
        self.assertIs(ixp.bridge, topo.get_bridge_name("physical_network1"))

        # Links
        self.assertEqual(len(topo.links), 13)

        interfaces = dict(topo.ases[ISD_AS("1-ff00:0:110")].links())
        link = interfaces[IfId(1)]
        subnet = ipaddress.ip_network("10.0.13.0/24")
        self.assertIs(link.bridge, topo.get_bridge_subnet(subnet))

        interfaces = dict(topo.ases[ISD_AS("1-ff00:0:111")].links())
        link = interfaces[IfId(1)]
        self.assertTrue(link.bridge.ip_network.overlaps(topo.default_link_subnet))
        link = interfaces[IfId(2)]
        self.assertTrue(link.bridge.ip_network.overlaps(topo.default_link_subnet))

        interfaces = dict(topo.ases[ISD_AS("2-ff00:0:211")].links())
        link = interfaces[IfId(1)]
        self.assertIs(link.bridge, topo.get_bridge_name("overlay_bridge1"))
        link = interfaces[IfId(2)]
        self.assertIs(link.bridge, topo.get_bridge_name("overlay_bridge1"))

        null = LinkEp()
        dummy_link_count = 0
        for link in topo.links:
            if link.type == LinkType.UNSET:
                dummy_link_count += 1
                self.assertEqual(link.ep_b, null)
            elif link.ep_b == null:
                self.assertEqual(link.type, LinkType.UNSET)
            self.assertNotEqual(link.ep_a, null)
        self.assertEqual(dummy_link_count, 6)

        # topo_file
        self.assertNotIn("link_subnet", topo_file['defaults'])
        self.assertNotIn("hosts", topo_file)
        self.assertNotIn("networks", topo_file)
        self.assertNotIn("coordinator", topo_file)
        self.assertNotIn("IXPs", topo_file)
        for link in topo_file['links']:
            self.assertNotIn('network', link)


    def test_remote_link_no_network(self):
        """Test `extract_topo_info` with a link between different hosts missing the 'network'
        specification.
        """
        topo_file = yaml.load(TEST_TOPO)
        del topo_file['links'][5]['network']

        with self.assertRaises(errors.InvalidTopo):
            extract_topo_info(topo_file)
