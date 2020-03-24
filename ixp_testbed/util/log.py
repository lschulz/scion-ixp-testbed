"""Helper functions for managing log files."""

import logging

from ixp_testbed.constants import LOG_FILE_NAME


def open_log_file(workdir):
    """Open the log file in the working directory and configure the main logger to use it."""
    log = logging.getLogger()
    handler = logging.FileHandler(workdir.joinpath(LOG_FILE_NAME))
    handler.setLevel(logging.DEBUG)
    handler.addFilter(logging.Filter("ixp_testbed"))
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s(%(filename)s:%(lineno)s): %(message)s"))
    log.addHandler(handler)
    logging.getLogger(__name__).debug("Log file opened.")
