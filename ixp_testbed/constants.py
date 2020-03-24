"""Constants used by other modules."""
import os

from lib.defines import DEFAULT_MTU as _DEFAULT_MTU

from topology.topo import DEFAULT_LINK_BW as _DEFAULT_LINK_BW


###############################
# Generated network directory #
##############################

LOG_FILE_NAME = "log"
"""Name of the log file created in the working directory."""

CONFIG_DATA_FILE = "config"
"""Name of the file storing the topology configuration in the working directory."""

PROCESSED_TOPO_FILE = "topology.topo"
"""Name of the topology file passed to 'scion.sh topology'."""

COORD_SCRIPT_NAME = "init_db.py"
"""Name of the script generated to initialized the coordinator's database."""

SSH_CLIENT_CONFIG = "ssh_config"
"""Name of the OpenSSH client configuration file for the coordinator."""

AS_IMAGE_TAR_FILE = "as_image.tar.gz"
"""Name of the file the SCION AS image is dumped to."""

COORD_IMAGE_TAR_FILE = "coord_image.tar.gz"
"""Name of the file the coordinator image is dumped to."""

##########
# Docker #
##########

DEFAULT_BRIDGE_NAME = "bridge"
"""Name of the default Docker bridge. All containers created without an explicitly specified network
(but still have a network stack) are connected to this bridge."""

OVERLAY_NETWORK_MAX_HOSTS = 8
"""Maximum number of different hosts that can run containers connected to the same Docker overlay
network. The number of hosts is restricted by this constant to allow reserving a fixed number
of IP address Docker assigns to the hosts themselves."""

#############################
# Remote Host Configuration #
#############################

KNOWN_HOSTS_FILE = "ssh/known_hosts"
"""Path to the known hosts file for host key verification."""

REMOTE_AS_IMAGE_TAR_FILE = "ixp_testbed_as_image.tar.gz"
"""Name of the temporary file the SCION AS image is loaded from on remote hosts."""

REMOTE_COORD_IMAGE_TAR_FILE = "ixp_testbed_coord_image.tar.gz"
"""Name of the temporary file the coordinator image is loaded from on remote hosts."""

######################
# SCION Docker image #
######################

SCION_USER = "scion"
"""User name of the SCION user in the SCION Docker container."""

SCION_PATH = "/home/scion/go/src/github.com/scionproto/scion/"
"""Location of the SCION source code within the SCION Docker image."""

SCION_TOPO_FILES_PATH = SCION_PATH + "topology/"
"""Location of the topology definition files within the SCION Docker image."""

##############################
# Master container and image #
##############################

STANDALONE_TOPO_AS_IMG_NAME = "ixp_testbed_standlone_as"
"""Name of the Docker image for standalone ASes (not getting their configuration from the
coordinator)."""

COORD_TOPO_AS_IMG_NAME = "ixp_testbed_as"
"""Name of the Docker image for ASes fetching their configuration from the coordinator."""

MASTER_CNTR_NAME = "master"
"""Name of the master container in which standalone topologies without a coordinator are build."""

MASTER_CNTR_MOUNT = "master"
"""Name of the directory passed to 'docker.sh' to create Docker volumes for the master container in.
"""

########################
# SCIONLab coordinator #
########################

COORD_IMG_NAME = "scionlab_coord"
"""Name of the Docker image containing the coordinator."""

SCIONLAB_PATH = "/home/%s/scionlab" % SCION_USER
"""Path to the scionlab repository in the coordinator container."""

COORD_NET_NAME = "coord"
"""Base name of the default Docker bridge connecting to the coordinator to ASes."""

COORD_PORT = 8000
"""TCP port the coordinator listens on."""

COORD_KEY_PATH = "ssh"
"""Location of SSH keys in the coordinator's container."""

COORD_PRIVATE_KEY_FILE = "coord_id_rsa"
"""Name of the coordinator's private SSH key file."""

COORD_PUBLIC_KEY_FILE = "coord_id_rsa.pub"
"""Name of the coordinator's public SSH key file."""

###############
# SCION Links #
###############

FIRST_IFID = 1
"""Smallest interface identifier to use."""

LINK_SUBNET_HOST_LEN = 3
"""Length of the host part of IP networks allocated for direct (non-IXP) SCION links."""

BR_DEFAULT_PORT = 50000
"""Default border router interface port."""

DEFAULT_LINK_TYPE = "PEER"
"""Default type of a link added to a running network."""

DEFAULT_MTU = _DEFAULT_MTU
"""Default MTU for a link added to a running network."""

DEFAULT_LINK_BW = _DEFAULT_LINK_BW
"""Default link bandwidth for a link added to a running network."""
