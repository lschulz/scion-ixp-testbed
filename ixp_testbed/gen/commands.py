"""Implementation of commands called from the command line interface."""

import logging
import os

import docker

from ixp_testbed.constants import CONFIG_DATA_FILE
from ixp_testbed.gen.generator import generate
from ixp_testbed.gen.plot import plot_topology
from ixp_testbed.topology import Topology
from ixp_testbed.util.fs import clear_directory
from ixp_testbed.util.log import open_log_file

log = logging.getLogger(__name__)


def generate_topology(args):
    """Generate a topology."""
    # Make sure the work directory exists and is empty.
    os.makedirs(args.workdir, exist_ok=True)
    if len(os.listdir(args.workdir)) > 0:
        if args.clear_workdir:
            log.info("Clearing work directory.")
            clear_directory(args.workdir)
        else:
            log.error("Work directory is not empty.")
            return

    open_log_file(args.workdir)
    dc = docker.from_env() # Connect to Docker daemon

    topo = generate(
        name = args.name,
        input_file_path = args.topo_file,
        workdir = args.workdir,
        sc = args.sc,
        dc = dc
    )
    topo.save(args.workdir.joinpath(CONFIG_DATA_FILE))


def plot(args):
    """Plot the topology."""
    topo = Topology.load(args.workdir.joinpath(CONFIG_DATA_FILE))
    plot_topology(topo)
