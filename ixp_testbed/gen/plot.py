"""Functions for plotting the testbed topology."""

from collections import defaultdict
import sys
from typing import Iterable, Tuple

from lib.types import LinkType

from ixp_testbed import errors
from ixp_testbed.scion import AS, Link
from ixp_testbed.topology import Topology
from lib.packet.scion_addr import ISD_AS


def plot_topology(topo: Topology, out=sys.stdout) -> None:
    """Create a graph description in graphviz dot syntax illustrating the given topology.

    :param topo: The topology to plot.
    :param out: Output text stream to write the result to.
    :raises InvalidTopo: If a problem with the topology has been encountered.
                         For example invalid link types.
    """
    isds = defaultdict(list)
    for isd_as, asys in topo.ases.items():
        isds[isd_as.isd_str()].append((isd_as, asys))

    out.write("digraph \"{}\" {{\n".format(topo.name if topo.name else "Topology"))
    out.write("nodesep=0.5;\n")
    out.write("ranksep=0.75;\n")

    # ISDs
    for name, ases in isds.items():
        _plot_isd(name, ases, topo.links, out)

    # inter-ISD links
    for link in topo.links:
        if link.ep_a.isd_str() != link.ep_b.isd_str():
            attributes = ""
            link_type = link.type.lower()
            if link_type == LinkType.CORE:
                attributes = "style=bold, dir=none, constraint=false"
            elif link_type == LinkType.PEER:
                attributes = "style=dashed, dir=none, constraint=false"
            elif link_type == LinkType.UNSET:
                continue # ignore dummy links
            else:
                out.write(str(link))
                raise errors.InvalidTopo() # inter-ISD parent-child links are not allowed
            out.write("\"{}\" -> \"{}\" [{}];\n".format(link.ep_a, link.ep_b, attributes))

    out.write("}\n")


def _plot_isd(name: str, ases: Iterable[Tuple[ISD_AS, AS]], links: Iterable[Link], out) -> None:
    """Create a subgraph for a set of ASes belonging to the same ISD.

    :param name: Name of the ISD.
    :param ases: ASes to include.
    :param links: Intra-ISD links.
    :param out: Output test stream.
    """
    out.write("subgraph \"cluster_isd{}\" {{\n".format(name))
    out.write("label=\"ISD{}\";\n".format(name))

    # ASes
    for isd_as, asys in ases:
        out.write("\"{}\" [shape=box{}];\n".format(isd_as, ", style=filled" if asys.is_core else ""))

    # intra-ISD links
    links_added = set()
    for _, asys in ases:
        for _, link in asys.links():
            if link not in links_added and link.ep_a.isd_str() == link.ep_b.isd_str():
                ep_a, ep_b = link.ep_a, link.ep_b
                attributes = "style=solid"
                link_type = link.type.lower()
                if link_type == LinkType.CORE:
                    attributes = "style=bold, dir=none"
                elif link_type == LinkType.PEER:
                    attributes = "style=dashed, dir=none, constraint=false"
                elif link_type == LinkType.PARENT:
                    ep_a, ep_b = ep_b, ep_a # make sure edge points from parent to child
                out.write("\"{}\" -> \"{}\" [{}];\n".format(ep_a, ep_b, attributes))
                links_added.add(link)

    # put the core ASes on the same rank
    out.write("{ rank=same; ")
    for isd_as, asys in ases:
        if asys.is_core:
            out.write("\"{}\"; ".format(isd_as))
    out.write("}\n")

    out.write("}\n")
