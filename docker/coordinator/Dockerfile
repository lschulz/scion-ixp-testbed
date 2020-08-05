FROM python:3.6

RUN apt-get update && apt-get install -y graphviz ssh libssl-dev

# Get the coordinator from GitHub:
RUN mkdir /scionlab
WORKDIR /scionlab
RUN git clone --branch ixp-testbed --recurse-submodules https://github.com/lschulz/scionlab.git .
# Alternativeley, use a local copy:
# COPY scionlab /scionlab
# WORKDIR /scionlab
RUN pip install --require-hashes -r requirements.txt -r dev-requirements.txt
RUN pip install --require-hashes -r scionlab_ixp/requirements.txt

RUN ./manage.py makemigrations
RUN ./manage.py migrate

ENTRYPOINT ./manage.py runserver 0.0.0.0:8000
