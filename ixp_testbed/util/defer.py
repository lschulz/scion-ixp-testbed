from contextlib import AbstractContextManager
from typing import Callable, List


class RollbackManager(AbstractContextManager):
    """Context manager collecting cleanup actions to execute on context exit.

    When the context is left, the cleanup actions are executed in reverse order.
    `success()` clears the registered actions without executing them.
    """
    def __init__(self):
        self.cleanup_actions: List[Callable[[], None]] = []


    def __exit__(self, exc_type, exc_value, traceback):
        while len(self.cleanup_actions) > 0:
            func = self.cleanup_actions.pop()
            func()


    def defer(self, cleanup_func: Callable[[], None]):
        self.cleanup_actions.append(cleanup_func)


    def success(self):
        self.cleanup_actions = []
