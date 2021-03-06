from typing import Any, Dict, Optional, Tuple, Union
from unittest import mock
from keys_management.secret_key import BaseSecretKeyDefinition, SecretKeyState

NAME = "name"
KEYS_STORE = "keys_store"
KEY = "key"

FORWARD_KEY = "encrypt"
BACK_KEY = "decrypt"

Keys = Union[str, Dict[str, str], Tuple]


class KeyDefForTest(BaseSecretKeyDefinition):
    keys: Keys
    next_keys: Optional[Keys]
    previous_keys: Optional[Keys]
    key_as_single: bool

    def __init__(
        self,
        name: str,
        keys: Keys,
        next_keys: Optional[Keys] = None,
        key_as_single: bool = False,
        **kwargs: Any
    ) -> None:
        self.key_as_single = key_as_single
        self.set_keys(keys)
        self.next_keys = next_keys
        self.previous_keys = None

        def side_effect() -> Keys:
            if isinstance(self.keys, Dict):
                return self.keys[FORWARD_KEY], self.keys[BACK_KEY]
            else:
                return self.keys

        super().__init__(name, mock.MagicMock(side_effect=side_effect), **kwargs)

    def _validate_properties(self) -> None:
        pass

    def set_keys(self, keys: Optional[Keys]) -> None:
        if keys is None:
            return
        if isinstance(keys, tuple):
            self.keys = {FORWARD_KEY: keys[0], BACK_KEY: keys[1]}
        elif isinstance(keys, (str, bytes)) and self.key_as_single:
            self.keys = keys
        else:
            self.keys = (
                keys if isinstance(keys, dict) else {FORWARD_KEY: keys, BACK_KEY: keys}
            )

    def set_next_as_keys(self, next_keys: Optional[Keys] = None) -> None:
        self.previous_keys = self.keys
        self.set_keys(self.next_keys if next_keys is None else next_keys)
        self.next_keys = None

    def get_key_state(self) -> SecretKeyState:
        pass

    def set_key_state(self, key_state: SecretKeyState) -> None:
        pass
