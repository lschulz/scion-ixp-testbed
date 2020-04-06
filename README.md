SCION IXP Testbed
=================
Software framework for development and testing of SCION in context of Internet Exchange Points
(IXPs). Runs [SCION](https://www.scion-architecture.net/) ASes and a modified
[SCIONLab Coordinator](https://github.com/netsec-ethz/scionlab) in Docker containers.


Installation (Ubuntu 18.04)
---------------------------
Install Docker, pip, and Open vSwitch (OVS is optional):
```bash
sudo apt-get install -y docker.io python3-pip openvswitch-switch
```

Add the current user to the docker group:
```bash
sudo gpasswd -a $USER docker
```

Clone the repository and install Python dependencies:
```bash
git clone https://github.com/lschulz/scion-ixp-testbed.git
cd ixp-testbed
pip3 install -r requirements.txt
```

Clone SCION and configure the environment:
```bash
echo 'export SC="$HOME/go/src/github.com/scionproto/scion"' >> ~/.profile
echo 'export PYTHONPATH=$SC/python:$PYTHONPATH' >> ~/.profile
source ~/.profile
mkdir -p $SC
git clone https://github.com/netsec-ethz/scion $SC/.
```


Topology Specification
----------------------
Topologies are specified by YAML files similar to those accepted by `$SC/scion.sh topology`.
Examples are available in [topologies/](/topologies).

In general there a three types of topologies:
1. **Standalone topologies** do not have a coordinator. They run one a single host and do not
support peering policies.
Example: [topologies/standalone/example.yaml](/topologies/standalone/example.yaml)

2. **Coordinator topologies** configure their ASes through a
[modified SCIONLab Coordinator](https://github.com/lschulz/scionlab/tree/ixp-testbed).
The modified coordinator supports automatic configuration of peering links based on policies set by
the ASes.
Example: [topologies/coordinator/example.yaml](/topologies/coordinator/example.yaml)

3. **Multi-host topologies** run Docker containers on multiple host computers and always include a
coordinator.
Example: [topologies/coordinator/multi-host_example.yaml](/topologies/coordinator/multi-host_example.yaml)


Network Types
-------------
ASes and the optional coordinator run in Docker containers. The containers are connected by network
bridges of one of these types:

Network Type    | Topo File Identifier | Local or Remote ASes | Maximum Size
----------------|----------------------|----------------------|-------------
Docker Bridge   | `docker_bridge`      | local                | unlimited
Open vSwitch    | `ovs_bridge`         | local                | unlimited
Docker Overlay  | `overlay`            | local and remote     | < 254 ASes
Port Forwarding | `host`               | remote               | unlimited

In a multi-host scenario, the coordinator has to connect to the AS containers with a Docker overlay
network. Overlay networks require all Docker hosts to be part of a [swarm](https://docs.docker.com/engine/swarm/).
To create a swarm, run
```bash
docker swarm init --advertise-addr <ip>
```
on one of the hosts. This host will be a manager node. Then follow the instructions on screen to
add the other hosts as worker nodes. To leave the swarm again, run
```bash
docker swarm leave --force
```


Running a topology
------------------
Create a topology with the command
```bash
./ixp-testbed.py topology topologies/coordinator/example.yaml
```
This will create the work directory `./network-gen` containing topology configuration files, the log
file (`./network-gen/log`), and the internal configuration and log files of local SCION ASes.

A different work directory can be specified by the `-w` option. The same work directory must be
given to all commands supposed to work on the same topology. To avoid name collisions, topologies
can be named using the `-n` option. The path to the SCION source code is expected in the environment
variable `$SC`. If another path should be used, it can be specified with the `--sc` option, which
like `-w` has to given to every command working on the topology. Taking all of the above together, a
topology can alternatively be created by
```bash
./ixp-testbed.py -w /path/to/workdir --sc /path/to/scion topology topologies/coordinator/example.yaml -n topo-name
```
The work directory must be empty. You can pass `--clear-workdir` to the command to clear the
directory first.

The Docker containers making up the SCION network are started with
```bash
./ixp-testbed.py cntrs start
```
Even without starting the container explicitly,
```bash
./ixp-testbed.py start
```
starts SCION in all AS containers. The command can have one of the three switches `-s`
(`--sequential`), `-p` (`--parallel`), or `-d` (`--detach`). With these switches, start commands are
issued to the ASes one after the other (sequential), without waiting for the previous command the
finish (parallel), or without even capturing the command output (detach). `-sequential` and
`--parallel` write output from the ASes to the log file for easier debugging, `--detach` does not.
-`--parallel` is the default. If many remote ASes are started at once, `--parallel` might run out
of SSH sessions allowed in parallel. In this case, `--sequential` or `--detach` must be used.

To get status information from all containers and ASes, run
```bash
./ixp-testbed.py status
```

SCION is shut down by
```bash
./ixp-testbed.py stop
```
This command has the same options as `start`.

To stop and remove the Docker containers and network bridges, run
```bash
./ixp-testbed.py cntrs stop
```
You can stop and clean up the topology manually with the following commands:
```bash
docker rm -f $(docker ps -a -q) # Removes *all* Docker containers.
docker network prune            # Removes all Docker networks.
sudo ovs-vsctl show             # Prints all OVS bridges.
sudo ovs-vsctl del-br <br-name> # For each bridge the topology created.
```

### Authentication at remote hosts
To run a topology spanning multiple host computers, the script needs SSH access to them. Only public
key authentication is supported. A private key file can be specified in the topology definition.
Unfortunately, Docker uses a different SSH client ([Paramiko](http://www.paramiko.org/)) internally
than we use ([ssh2-python](https://github.com/ParallelSSH/ssh2-python)). We cannot pass the
specified key through Docker, therefore it is preferred to run `ssh-agent` and add the required keys
with `ssh-add`. For example, like this:
```bash
eval `ssh-agent`
ssh-add ~/.ssh/scion_id_rsa
```

### Running commands and testing connectivity
`ixp-testbed.py` offers the subcommand `exec` to run commands in AS containers. `exec` takes a
regular expression and a command. The command is executed in all ASes whose ISD-AS identifier
matches the regular expression. Within the command, the ISD-AS string is substituted for `{isd_as}`
and `{file_fmt}` in regular and file name format, respectively. The [scripts/](/scripts) directory
offers a few scripts using this command to run diagnostic tools in standalone or coordinator
configured ASes. For example,
```bash
./scripts/coordinator/ping.sh ./network-gen 1-ff00:0:110
```
pings AS `1-ff00:0:110` from all other ASes in the topology.

There is also the subcommand `update`, which initiates a configuration update from the coordinator
in one or multiple ASes.

### Configuring links (Standalone topologies)
In standalone topologies, all SCION links are listed by the command
```bash
./ixp-testbed.py link list
```
The list command will show dummy links with a zero endpoint, if a peering coordinator is used.
These links keep the affected ASes connected to IXPs, even if no static peering links are configured
in the topology file.

Links using an IXP can be added, modified, or removed with the subcommands `link add`,
`link modify`, and `link remove`. If the topology contains a coordinator, these commands are of
limited use, since the coordinator will not know about these modifications and overwrite them one
the next configuration update.

### Configuring peering policies (Coordinator topologies)
The `policy` subcommand provides a simple way to configure AS peering policies. For example, a new
policy is installed by
```bash
./ixp-testbed.py policy create 1-ff00:0:112 --data '{"1": {"AS": {"accept": ["ff00:0:113"]}}}'
```
Policies are deleted by `policy delete`. The currently active policies can be retrieved by
`policy get`. To view the peering connections resulting from the policies, use `policy get_peers`.

Extras
------
There are some additional command to debug and evaluate topologies:

### Plotting the topology
The subcommand `plot` prints a topology graph in [Graphviz](https://www.graphviz.org/) dot syntax.
It can be used like
```bash
./ixp-testbed.py plot | dot -Tsvg -o topo.svg
```
to visualize the topology.

### Debug gen folder
The script [gen-tool.py](/gen-tool.py) prints and optionally modifies the IP addresses and ports
used by a SCION AS. For example,
```bash
./gen-tool.py ./network-gen/1-ff00_0_110/gen
```
prints all IPs and ports used by AS `1-ff00:0:110`. The switch `-b` limits output to border routers,
and `-r` interactively asks for new addresses to replace the current ones.

### Measure AS CPU utilization
The CPU utilization of ASes and services within the ASes is measured by `./ixp-testbed.py stats`.
The command takes a number of options: The ASes from which to take measurements are specified by
a regular expression provided via the `-p` option, similar to the `exec` and `update` subcommands.
Additionally, a list of executables to measure individually can be provided as `--services`. The
number of measurements and the measurement interval in seconds are specified by `-c` and `-i`,
respectively. For example:
```bash
./ixp-testbed.py stats -i 10 -c 1 -p '1-ff00:0:...' --services bin/border bin/beacon_srv bin/path_srv
```

### Monitoring AS metrics
The SCION border routers, and the beacon, path, and certificate servers expose
[Prometheus](https://prometheus.io/) metrics. A containerized Prometheus server scraping these
metrics can be configured in the topology file. At the moment only beacon, path, and certificate
server metrics are supported.
Example: [topologies/coordinator/prometheus.yaml](/topologies/coordinator/prometheus.yaml)

Development
-----------
### Running the tests
Tests can be run with `python3 -m unittest discover`.

### Updating Docker images
The `./ixp-testbed.py topology` commands builds the SCION images `scion_base` and `scion`, and based
on them the images `scionlab_coord`, `ixp_testbed_as`, and `ixp_testbed_standalone_as`, if they are
not found. Similarly, `./ixp-testbed.py start` copies local images not found on remote Docker hosts
to them. To rebuild the images, delete or rename the old ones first.

### Managing dependencies
[pip-tools](https://pypi.org/project/pip-tools/) is used for managing dependencies.
