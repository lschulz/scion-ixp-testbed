FROM scion:latest

USER scion
RUN sudo apt update
RUN sudo apt install -y python3-venv graphviz

# Get the coordinator from GitHub:
WORKDIR /home/scion
RUN git clone https://github.com/lschulz/scionlab.git
WORKDIR /home/scion/scionlab
RUN git checkout ixp-testbed
# Alternativeley, use a local copy:
# COPY --chown=scion:users scionlab /home/scion/scionlab
# WORKDIR /home/scion/scionlab

ENV VIRTUAL_ENV=/tmp/scionlab
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel
RUN pip install --require-hashes -r requirements.txt -r dev-requirements.txt

ENV PYTHONPATH=/home/scion/go/src/github.com/scionproto/scion/python/:/home/scion/go/src/github.com/scionproto/scion
RUN ./manage.py makemigrations
RUN ./manage.py migrate

ENTRYPOINT ./manage.py runserver 0.0.0.0:8000
