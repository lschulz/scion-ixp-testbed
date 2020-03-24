#!/usr/bin/python3

import argparse
import json
import os
from pathlib import Path


class GenFolder:
    def __init__(self, gen_path):
        self._gen_path = gen_path

    def list_services(self, br_only, rewrite):
        """List SCION services of all ASes defined in the gen folder on stdout.

        :param br_only: List border routers only.
        :param rewrite: Allow the user to interactively change the underlying IP addresses.
        :return: A dictionary mapping old underlay addresses to new underlay addresses.
        """
        self._br_only = br_only
        self._rewrite = rewrite
        self._mapping = dict()
        self._enumerate_isds()
        return self._mapping

    def _enumerate_isds(self):
        with os.scandir(self._gen_path) as iter:
            for dir in iter:
                if dir.name.startswith("ISD"):
                    print("### \033[37;1m{}\033[0m ###".format(dir.name))
                    self._enumerate_ases(dir.path)

    def _enumerate_ases(self, isd_path):
        with os.scandir(isd_path) as iter:
            for dir in iter:
                if dir.name.startswith("AS"):
                    print(" ## \033[31;1m{}\033[0m ##".format(dir.name))
                    topo = self._enumerate_services(Path(dir.path).joinpath("endhost/topology.json"))
                    if len(self._mapping) > 0:
                        self._install_topology_file(topo, dir.path)

    def _enumerate_services(self, topo_file_path):
        with open(topo_file_path, 'r') as topo_file:
            topo = json.load(topo_file)
            _, underlay_ip = topo['Overlay'].split("/")

            if not self._br_only:
                # Zookeeper Service
                if 'ZookeeperService' in topo:
                    for zoo_name, zoo in topo['ZookeeperService'].items():
                        print("  \033[36;1mZookeeper\033[0m \033[33;1m{}\033[0m".format(zoo_name))
                        print(end="   ")
                        self._print_addr(zoo)

                # Beacon Service
                for bs_name, bs in topo['BeaconService'].items():
                    print("  \033[36;1mBeacon Service\033[0m \033[33;1m{}\033[0m".format(bs_name))
                    print(end="   ")
                    self._print_addr(bs['Addrs'][underlay_ip]['Public'])

                # Certificate Service
                for cs_name, cs in topo['CertificateService'].items():
                    print("  \033[36;1mCertificate Service\033[0m \033[33;1m{}\033[0m".format(cs_name))
                    print(end="   ")
                    self._print_addr(cs['Addrs'][underlay_ip]['Public'])

                # Path Service
                for ps_name, ps in topo['PathService'].items():
                    print("  \033[36;1mPath Service\033[0m \033[33;1m{}\033[0m".format(ps_name))
                    print(end="   ")
                    self._print_addr(ps['Addrs'][underlay_ip]['Public'])

            # Border Routers
            for br_name, br in topo['BorderRouters'].items():
                print("  \033[36;1mBorder Router\033[0m \033[33;1m{}\033[0m".format(br_name))
                if not self._br_only:
                    print("   \033[32mControl\033[0m : ", end="")
                    self._print_addr(br['CtrlAddr'][underlay_ip]['Public'])
                    print("   \033[32mInternal\033[0m: ", end="")
                    self._print_br_if_addr(br['InternalAddrs'][underlay_ip]['PublicOverlay'])
                for iface_name, iface in br['Interfaces'].items():
                    print("   \033[35mInterface\033[0m {} to \033[33;1m{}\033[0m ({})".format(
                        iface_name, iface['ISD_AS'], iface['LinkTo']))
                    print("    \033[32mLocal\033[0m : ", end="")
                    self._print_br_if_addr(iface['PublicOverlay'])
                    print("    \033[32mRemote\033[0m: ", end="")
                    self._print_br_if_addr(iface['RemoteOverlay'])

            print()
        return topo

    def _print_addr(self, addr):
        """Print the underlay address of a service."""
        old_addr = (addr['Addr'], addr['L4Port'])
        new_addr = self._print_address(old_addr)
        addr['Addr'], addr['L4Port'] = new_addr

    def _print_br_if_addr(self, overlayAddr):
        """Print the underlay address of a border router interface."""
        old_addr = (overlayAddr['Addr'], overlayAddr['OverlayPort'])
        new_addr = self._print_address(old_addr)
        overlayAddr['Addr'], overlayAddr['OverlayPort'] = new_addr

    def _print_address(self, old_addr):
        """Print an underlay address and optionally ask the user for a new address.

        Changes to the address are recorded in `self._mapping`.
        The user is only asked to enter a new address if the same address has not been rewritten
        elsewhere already.

        :param old_addr: The original underlay address.
        :returns: The new address entered by the user or `old_addr` if the address should not be
                  changed.
        """
        print("[{}]:{}".format(*old_addr), end="")
        if not self._rewrite:
            print()
            return old_addr

        print(" => ", end="")

        if old_addr in self._mapping:
            # address has already been remapped
            new_addr = self._mapping[old_addr]
            print("[{}]:{}".format(*new_addr))
        else:
            # ask user for new address
            user_input = input().split()
            if len(user_input) not in [1, 2]:
                new_addr = old_addr # keep old address
            else:
                if len(user_input) == 2:
                    new_addr = tuple(user_input)
                else:
                    new_addr = (user_input[0], old_addr[1])
                self._mapping[old_addr] = new_addr

        return new_addr


    def _install_topology_file(self, topo, as_path):
        """Overwrite the topology files of an AS.

        :param topo: New JSON topology structure
        :param as_path: Path to the AS folder
        """
        with os.scandir(as_path) as iter:
            for dir in iter:
                topo_path = Path(dir.path).joinpath("topology.json")
                if topo_path.exists():
                    with open(topo_path, 'w') as topo_file:
                        json.dump(topo, topo_file, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Print the underlay addresses of SCION services defined in the given gen folder.")
    parser.add_argument("path", type=Path, help="Path to the gen folder")
    parser.add_argument("-b", "--br-only", dest='br_only', action='store_true',
        help="List border routers only.")
    parser.add_argument("-r", "--rewrite", dest='rewrite', action='store_true',
        help="Interactively rewrite the overlay addresses.")
    args = parser.parse_args()

    mapping = GenFolder(args.path).list_services(args.br_only, args.rewrite)
    if len(mapping) > 0:
        print("Changes:")
    for a, b in mapping.items():
        print("{}:{} => {}:{}". format(*a, *b))
