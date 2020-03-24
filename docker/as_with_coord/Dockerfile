FROM scion:latest

USER scion
RUN sudo apt update

# Install 'ip' and 'ping' commands.
RUN sudo apt-get install -y iproute2 iputils-ping

# Install modified scionlab-config script.
COPY --chown=scion:users scionlab-config-user /home/scion/go/src/github.com/scionproto/scion/
RUN chmod 755 /home/scion/go/src/github.com/scionproto/scion/scionlab-config-user
COPY --chown=root:root scionlab-config /usr/bin/
RUN sudo chmod 755 /usr/bin/scionlab-config

# Script for generating TLS certificates.
COPY --chown=scion:users gen-certs.sh /home/scion/go/src/github.com/scionproto/scion/
RUN chmod 755 /home/scion/go/src/github.com/scionproto/scion/gen-certs.sh

# Install and configure an SSH server.
RUN sudo apt-get install -y openssh-server
COPY --chown=root:root sshd_config /etc/ssh/
RUN sudo chmod 644 /etc/ssh/sshd_config

# Build SCION.
RUN ./scion.sh build
