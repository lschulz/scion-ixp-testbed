"""Exceptions raised by the other modules."""

from typing import Optional


class IxpTestbedError(Exception):
    """Base class for all other exceptions. Not used directly."""

class InvalidTopo(IxpTestbedError):
    """The topology is invalid."""

class InvalidName(IxpTestbedError):
    """Object name invalid."""

class SubnetOverlap(IxpTestbedError):
    """"IP subnets overlap."""

class NotAvailable(IxpTestbedError):
    """Some resource is not availabile at the moment."""

class NotFound(IxpTestbedError):
    """"Requested resource not found."""

class OutOfResources(IxpTestbedError):
    """Some resource has been exhausted."""

class CommandFailed(IxpTestbedError):
    """An external command failed."""

class ProcessError(IxpTestbedError):
    """An external process failed.

    :ivar exit_code: The return value of the process.
    :ivar output: Process output if available.
    """
    def __init__(self, exit_code, output = None):
        self.exit_code: int = exit_code
        self.output: Optional[str] = output

    def __repr__(self):
        if self.output is not None and len(self.output) > 0:
            return "ProcessError (%s):\n%s" % (self.exit_code, self.output)
        else:
            return "ProcessError (%s)" % self.exit_code
