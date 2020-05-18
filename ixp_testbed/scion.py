"""Classes representing objects in a SCION topology."""

import io
import ipaddress
import logging
import re
from typing import Dict, Iterable, List, Optional, Tuple, Union

from ixp_testbed.address import IfId, IpAddress, ISD_AS, UnderlayAddress
from ixp_testbed.gen.interfaces import pick_unused_ifid
from ixp_testbed.host import Host
from ixp_testbed.util.typing import unwrap

log = logging.getLogger(__name__)


class LinkEp(ISD_AS):
    """Similar to topology.topo.LinkEP with some extensions for easier construction."""
    PATTERN = re.compile(r"(\d+-[^#\-]+)(?:-([^#]*))?(?:#(\d+))?")

    def __init__(self, initializer: Union[None, str, ISD_AS] = None, *,
        ifid: Optional['IfId'] = None, br_label: Optional[str] = None):
        """Construct a link endpoint from a string or its individual components.

        :param initializer: Link endpoint in textual representation, or AS of the endpoint. In the
                            latter case, IFID and BR label can be specified by in additional
                            arguments. If this argument is None, the endpoint ISD-AS number is
                            initialized to all zeros.
        :param ifid: Interface ID of the endpoint.
        :param br_label: Label for the endpoint's border router used during topology construction.
        """
        self.ifid = self.br_label = None
        if initializer is None:
            super().__init__()

        elif isinstance(initializer, ISD_AS):
            super().__init__(initializer)
            self.ifid = ifid
            self.br_label = br_label

        else:
            match = self.PATTERN.match(initializer)
            if match is None:
                pass
            else:
                super().__init__(match[1])
                self.br_label = match[2]
                if match[3] is not None:
                    self.ifid = int(match[3])


    def br_name(self):
        if self.br_label is not None:
            return "%s-%s" % (self.file_fmt(), self.br_label)
        else:
            return None


class Link:
    """SCION link between two ASes.

    :ivar ep_a: First endpoint.
    :ivar ep_b: Second endpoint.
    :ivar type: SCION link type. CORE, CHILD, PEER, etc.
    :ivar ep_a_underlay: Underlay address assigned to the first endpoint.
    :ivar ep_b_underlay: Underlay address assigned to the second endpoint.
    :ivar bridge: The network bridge on which this link exists.
    """
    def __init__(self, a: LinkEp, b: LinkEp, type: str):
        self.ep_a: LinkEp = a
        self.ep_b: LinkEp = b
        self.type = type # LinkType
        self.ep_a_underlay: Optional[UnderlayAddress] = None
        self.ep_b_underlay: Optional[UnderlayAddress] = None
        self.bridge: Optional['Bridge'] = None

    def __str__(self):
        return "Link: {}#{} ({}) -> {}#{} ({}) {} [{}]".format(
            self.ep_a, self.ep_a.ifid, self.ep_a_underlay,
            self.ep_b, self.ep_b.ifid, self.ep_b_underlay,
            self.type, self.bridge.name if self.bridge else "None")

    def is_dummy(self):
        """Checks whether the link is a dummy link, i.e., one of its endpoints is zero."""
        return self.ep_a.is_zero() or self.ep_b.is_zero()

    def get_underlay_addresses(self, link_ep: ISD_AS):
        """Get the underlay addresses associated with the given endpoint.

        :returns: A pair of the first the local and second the remote underlay address as seen from
        the perspective of the given endpoint.
        :raises KeyError: `link_ep` is not an endpoint of this link.
        """
        if link_ep == self.ep_a:
            return (self.ep_a_underlay, self.ep_b_underlay)
        elif link_ep == self.ep_b:
            return (self.ep_b_underlay, self.ep_a_underlay)
        else:
            raise KeyError(link_ep)

    def get_other_endpoint(self, link_ep: LinkEp) -> LinkEp:
        """Get the endpoint on the other side of the link as seen from the given endpoint.

        :raises KeyError: `link_ep` is not an endpoint of this link.
        """
        if link_ep == self.ep_a:
            return self.ep_b
        elif link_ep == self.ep_b:
            return self.ep_a
        else:
            raise KeyError(link_ep)

    def is_endpoint(self, ep: LinkEp) -> bool:
        """Returns True, if `ep` is an endpoint of this link."""
        return ep == self.ep_a or ep == self.ep_b


class BorderRouter:
    """Representation of a SCION border router.

    :ivar id: Border router ID. Unique per AS. Usually starting at one.
    :ivar links: Mapping of interface IDs (unique per AS) to links.
    """
    def __init__(self, id: int):
        self.id = id
        self.links: Dict[IfId, Link] = {}

    def get_name(self, isd_as: ISD_AS) -> str:
        """Construct the name of the border router as found in topology.json files.

        :param isd_as: AS the border router belongs to.

        Example:
        BorderRouter(1).get_name(ISD_AS("1-ff00_0_110")) == 'br1-ff00_0_110-1'
        """
        return "br{}-{}".format(isd_as.file_fmt(), self.id)


class AS:
    """Representation of a SCION AS running in a Docker container.

    :ivar host: Host running the AS.
    :ivar container_id: ID of the container the AS runs in. `None` if no container exists.
    :ivar is_core: Whether the AS is a core AS.
    :ivar is_attachment_point: Whether the AS is configured as an 'attachment point'. The SCIONLab
                               coordinator connects UserASes to attachment points. The coordinator
                               requires SSH access to the containers running attachment points.
    :ivar owner: The user considered the ASes owner by the coordinator. An AS is a 'UserAS' if it
                 has an owner, otherwise it is an 'Infrastructure AS'.
    :ivar border_routers: List of border routers in this AS.
    """
    def __init__(self, host: Host, is_core: bool):
        self.host: Host = host
        self.container_id: Optional[str] = None
        self.is_core = is_core
        self.is_attachment_point = False
        self.owner: Optional[str] = None
        self.border_routers: List[BorderRouter]

    def get_container(self):
        """Get the container this AS is running in if `self.container_id` is not None.

        :raises docker.errors.NotFound: If Docker could not find the container.
        """
        return self.host.docker_client.containers.get(self.container_id)

    def is_user_as(self) -> bool:
        """Check whether this is a user AS."""
        return self.owner != None

    def links(self) -> Iterable[Tuple[IfId, Link]]:
        """Returns an iterator over all links connected to this AS."""
        for br in self.border_routers:
            for ifid, link in br.links.items():
                yield (ifid, link)

    def get_border_router(self, ifid: IfId) -> Optional[BorderRouter]:
        """Get the border router the interface with ID `ifid` belongs to.

        :return: Border router instance or `None` if no border router has an interface with the
                 given ID.
        """
        for br in self.border_routers:
            if ifid in br.links:
                return br
        else:
            return None

    def get_unused_ifid(self) -> IfId:
        """Returns the smallest unused interface identifier."""
        ifids = []
        for br in self.border_routers:
            ifids.extend(br.links.keys())
        ifids.sort()
        return pick_unused_ifid(ifids)

    def get_cntr_ip(self, network: str) -> IpAddress:
        """Get the IP address of the AS container in the given network. Requirers the AS container
        to exist.

        This methods retrieves the IP addresses actually in use by Docker right now, not the
        assignments from the Bridge instances of the ASes links. Therefore it can get IP addresses
        from networks which were not explicitly configured by this script, like the default Docker
        bridge.
        """
        template = "'{{with index .NetworkSettings.Networks \"%s\"}}{{.IPAddress}}{{end}}'" % network
        try:
            _, output = self.host.run_cmd(
                ["docker", "inspect", "-f", template, unwrap(self.container_id)],
                check=True, capture_output=True)
            return ipaddress.ip_address(output.strip("'\n"))
        except Exception:
            log.error("Could not retrieve IP address of container '%s' in network '%s'.",
            self.container_id, network)
            raise
