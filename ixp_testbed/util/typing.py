"""Support functions to help with type hints."""

from typing import Any, Optional, TypeVar


T = TypeVar('T')
def unwrap(opt_value: Optional[T]) -> Any:
    """Asserts that `opt_value` contains a value and returns it."""
    assert opt_value is not None
    return opt_value
