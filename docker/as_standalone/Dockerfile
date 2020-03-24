FROM scion:latest

USER scion
RUN sudo apt update

# Install 'ip' and 'ping' commands.
RUN sudo apt-get install -y iproute2 iputils-ping

# Script for generating TLS certificates.
COPY --chown=scion:users gen-certs.sh /home/scion/go/src/github.com/scionproto/scion/
RUN chmod 755 /home/scion/go/src/github.com/scionproto/scion/gen-certs.sh

# Build SCION.
RUN ./scion.sh build
