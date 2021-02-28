from typing import Callable, Union, Dict, Optional
from unittest import mock
NAME = 'name'
KEYS_STORE = 'keys_store'
KEY = 'key'

Keys = Union[str, Dict[str, str]]


class KeyDef:
    name: str
    keys: Keys
    keys_store: Callable
    next_keys: Optional[Keys]
    previous_keys: Optional[Keys]

    def __init__(self, name: str, keys: Keys, next_keys: Optional[Keys] = None):
        self.name = name
        self.set_keys(keys)
        self.keys_store = mock.MagicMock(side_effect=lambda: self.keys)
        self.next_keys = next_keys
        self.previous_keys = None

    def set_keys(self, keys):
        self.keys = keys if isinstance(keys, dict) else {'encrypt': keys, 'decrypt': keys}

    def set_next_as_keys(self, next_keys: Optional[Keys] = None):
        self.previous_keys = self.keys
        self.set_keys(self.next_keys if next_keys is None else next_keys)
        self.next_keys = None


