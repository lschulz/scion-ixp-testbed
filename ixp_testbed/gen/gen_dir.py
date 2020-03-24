"""Functions for manipulating the gen folder."""

import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping

from lib.packet.scion_addr import ISD_AS

import ixp_testbed.constants as const
from ixp_testbed.address import IfId
from ixp_testbed.scion import AS, BorderRouter, Link
from ixp_testbed.topology import Topology


def modify_as_topo_file(gen_path: Path, isd_as: ISD_AS, mod_func):
    """Modify the topology.json files of an AS.

    :param gen_path: Path to the gen folder.
    :param isd_as: AS whose topology files to modify.
    :param mod_func: The function that that is doing the actual modifications by mutating the
                     dictionary it is given.
    """
    as_path = gen_path.joinpath("ISD{}/AS{}/".format(isd_as.isd_str(), isd_as.as_file_fmt()))
    topo_file_path = as_path.joinpath("endhost/topology.json")

    topo_file = None
    with open(topo_file_path, 'r') as file:
        topo_file = json.load(file)

    mod_func(topo_file)
    _install_topo_file(topo_file, as_path)


def modify_topo_files(gen_path: Path, topo: Topology):
    """Modify all AS in the topology by replacing the underlay addresses of the border routers.

    :param gen_path: Path to the gen folder to modify.
    :param topo: Topology object providing the new interface addresses.
    """
    for isd_as, asys in topo.ases.items():
        modify_as_topo_file(gen_path, isd_as,
            lambda topo_file: _update_underlay_addresses(topo_file, isd_as, asys))


def _update_underlay_addresses(topo_file: Mapping[str, Any], isd_as: ISD_AS, asys: AS):
    """Update the underlay addresses of the border router interfaces to match the given AS object.

    :param topo_file: Parsed topology.json file to modify.
    :param isd_as: AS the topology file belongs to.
    :param asys: AS the topology file belongs to.
    """
    for br in asys.border_routers:
        br_name = br.get_name(isd_as)
        interfaces = topo_file['BorderRouters'][br_name]['Interfaces']
        for ifid, iface in interfaces.items():
            local, remote = br.links[IfId(int(ifid))].get_underlay_addresses(isd_as)
            iface['PublicOverlay']['Addr'] = str(local.ip)
            iface['PublicOverlay']['OverlayPort'] = int(local.port)
            iface['RemoteOverlay']['Addr'] = str(remote.ip)
            iface['RemoteOverlay']['OverlayPort'] = int(remote.port)


def add_br_interface(topo_file: Mapping[str, Any],
    br: BorderRouter, ifid: IfId, local_as: ISD_AS, link: Link, link_properties: Mapping[str, Any]):
    """Add a new interface to a border router.

    :param topo_file: Parsed topology.json file to modify.
    :param br: Border router to which an interface is added.
    :param ifid: ID of the new interface. IDs must be unique pre AS.
    :param local_as: The local endpoint of the link connected to the new interface.
    :param link: The link connected to the interface.
    :param link_properties: Additional link properties like link type.
    """
    interfaces = topo_file['BorderRouters'][br.get_name(local_as)]['Interfaces']
    local, remote = link.get_underlay_addresses(local_as)
    iface = {
        "ISD_AS": str(link.get_other_endpoint(local_as)),
        "LinkTo": link_properties.get('type', const.DEFAULT_LINK_TYPE),
        "Bandwidth": link_properties.get('bandwidth', const.DEFAULT_LINK_BW),
        "MTU": link_properties.get('mtu', const.DEFAULT_MTU),
        "Overlay": "UDP/IPv4" if local.ip.version == 4 else "UDP/IPv6",
        "PublicOverlay": {
            "Addr": str(local.ip),
            "OverlayPort": int(local.port)
        },
        "RemoteOverlay": {
            "Addr": str(remote.ip),
            "OverlayPort": int(remote.port)
        }
    }
    interfaces[str(ifid)] = iface


def modify_br_interface_properties(topo_file: Mapping[str, Any],
    br: BorderRouter, ifid: IfId, local_as: ISD_AS, link_properties: Mapping[str, Any]):
    """Modify an existing BR interface.

    :param topo_file: Parsed topology.json file to modify.
    :param br: Border router the interface belongs to.
    :param ifid: ID of the interface.
    :param local_as: The AS the border router belongs to.
    :param link_properties: The new link properties. Properties not found in this mapping are left unchanged.
    """
    interfaces = topo_file['BorderRouters'][br.get_name(local_as)]['Interfaces']
    iface = interfaces[str(ifid)]
    iface['LinkTo'] = link_properties.get('type', const.DEFAULT_LINK_TYPE)
    iface['Bandwidth'] = link_properties.get('bandwidth', const.DEFAULT_LINK_BW)
    iface['MTU'] = link_properties.get('mtu', const.DEFAULT_MTU)


def remove_br_interface(topo_file: Mapping[str, Any], br: BorderRouter, ifid: IfId, local_as: ISD_AS):
    """Remove an interface from a border router.

    :param topo_file: Parsed topology.json file to modify.
    :param br: Border router from which the interface is removed.
    :param ifid: ID of the interface to remove.
    :param local_as: The AS the border router belongs to.
    """
    interfaces = topo_file['BorderRouters'][br.get_name(local_as)]['Interfaces']
    del interfaces[str(ifid)]


def _install_topo_file(topo_file: Mapping[str, Any], as_path: Path):
    """Overwrite all topology files in the given AS folder.

    :param topo_file: New topology file contentents.
    :param as_path: Path to the AS within the gen folder, e.g., "ISD1/ASff00_0_110/".
    """
    with os.scandir(as_path) as iter:
        for dir in iter:
            topo_path = Path(dir.path).joinpath("topology.json")
            if topo_path.exists():
                with open(topo_path, 'w') as output_file:
                    json.dump(topo_file, output_file, indent=2)


def create_as_mount_dirs(workdir: Path, topo: Topology):
    """Creates a directory for each AS container and copies the necessary files from the master
    directory.

    :param workdir: Path to the topologies working directory. This is were the AS directories are
                    created.
    :param topo: The topology database.
    """
    master_path = workdir.joinpath(const.MASTER_CNTR_MOUNT)

    for isd_as in topo.ases.keys():
        as_gen_path = "gen/ISD{}/AS{}/".format(isd_as.isd_str(), isd_as.as_file_fmt())
        output_path = workdir.joinpath(isd_as.file_fmt())

        # Create AS output directory
        os.mkdir(output_path)

        # Copy gen folder
        output_gen_path = output_path.joinpath("gen")
        os.mkdir(output_gen_path)
        for entry in os.scandir(master_path.joinpath("gen")):
            if entry.is_file():
                shutil.copyfile(entry.path, str(output_gen_path.joinpath(entry.name)))
            elif entry.is_dir():
                if not str(entry.name).startswith("ISD"): # exclude ISD directories
                    shutil.copytree(entry.path, output_gen_path.joinpath(entry.name))

        # Copy the configuration of the current AS
        shutil.copytree(master_path.joinpath(as_gen_path), output_path.joinpath(as_gen_path))


def create_as_mount_dirs_coord(workdir: Path, topo: Topology):
    """Creates a directory for each AS container running on the local computer.

    ASes running on remote hosts do not have Docker volumes to make their configuration easily
    accessable from thehost.

    This function is used instead of create_as_mount_dirs() if the coordinator is enabled.

    :param workdir: Path to the topologies working directory. This is were the AS directories are
                    created.
    :param topo: The topology database.
    """
    for isd_as, asys in topo.ases.items():
        if asys.host.is_local():
            output_path = workdir.joinpath(isd_as.file_fmt())

            # Create AS output directory
            os.mkdir(output_path)
