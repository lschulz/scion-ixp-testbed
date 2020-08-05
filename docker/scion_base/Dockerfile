from ubuntu:18.04

ARG SCION_UID=1000
ARG SCION_GID=1000

RUN apt-get update && apt-get upgrade -y

# Install first batch of dependencies
# Note: g++, unzip, zip are requiered by Bazel
# Note iproute2, iputils-ping are installed for easier debugging
RUN apt-get install -y sudo git wget g++ unzip zip iproute2 iputils-ping

# Create scion user
RUN groupadd -g ${SCION_GID:?} scion
RUN useradd -m -s /bin/bash -u ${SCION_UID:?} -g scion -G sudo scion
RUN gpasswd -a scion sudo
RUN echo 'scion ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/scion

USER scion
WORKDIR /home/scion
ENV HOME=/home/scion

# Install Bazel
RUN wget --no-verbose https://github.com/bazelbuild/bazel/releases/download/3.2.0/bazel-3.2.0-installer-linux-x86_64.sh
RUN bash ./bazel-3.2.0-installer-linux-x86_64.sh --user
RUN rm ./bazel-3.2.0-installer-linux-x86_64.sh
RUN echo 'source /home/scion/.bazel/bin/bazel-complete.bash' >> ~/.bashrc
ENV PATH="$PATH:$HOME/bin"

# Install SCION
ENV SC="$HOME/go/src/github.com/scionproto/scion"
ENV PYTHONPATH="$SC/python:$PYTHONPATH"
RUN mkdir -p $SC
RUN git clone --branch v2020.03 https://github.com/netsec-ethz/scion $SC/.

# Install SCION dependencies
# Note: ./env/deps fails if setuptools is not installed first
WORKDIR /home/scion/go/src/github.com/scionproto/scion/
RUN sudo apt-get install -y sudo python3-pip python3-setuptools
RUN APTARGS='-y' ./env/deps

# Build SCION
# Note: Building and supervisor-wildcards require Python 2.7
# Note: supervisor-wildcards adds mstart, mstop, mrestart, and mstatus commands
RUN sudo apt-get install -y python python-pip supervisor
RUN pip install supervisor-wildcards
RUN ./scion.sh build

# Get IP address of the default Docker bridge
ENV DOCKER_IF=eth0
RUN echo "export DOCKER0=`./tools/docker-ip`" >> ~/.profile

# Create dispatcher and sciond directories with correct owner
RUN sudo mkdir -p /run/shm/dispatcher
RUN sudo chown scion /run/shm/dispatcher && chgrp scion /run/shm/dispatcher
RUN sudo mkdir -p /run/shm/sciond
RUN sudo chown scion /run/shm/sciond && chgrp scion /run/shm/sciond
