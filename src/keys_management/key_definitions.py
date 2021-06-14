from abc import ABC, abstractmethod
from typing import Iterable, Tuple, Dict, Iterator
from keys_management.secret_key.key_definition import BaseSecretKeyDefinition

class KeysDefnitions(ABC):
    @abstractmethod
    def get(self, key_name: str) -> BaseSecretKeyDefinition:
        pass

    @abstractmethod
    def set(self, key_name: str, definition: BaseSecretKeyDefinition) -> None:
        pass

    @abstractmethod
    def get_all_names(self) -> Iterable[str]:
        pass

    @abstractmethod
    def get_all_definitions(self) -> Iterable[BaseSecretKeyDefinition]:
        pass

    @abstractmethod
    def items(self) -> Iterable[Tuple[str, BaseSecretKeyDefinition]]:
        pass


    def __iter__(self) -> Iterator[str]:
        return iter(self.get_all_names())

    def __contains__(self, key_name: str) -> bool:
        try:
            return self.get(key_name) is not None
        except:
            return False

    def __getitem__(self, key_name: str) -> BaseSecretKeyDefinition:
        return self.get(key_name)

    def __setitem__(self, key_name: str, definition: BaseSecretKeyDefinition) -> None:
        self.set(key_name, definition)


class DefaultKeysDefnitions(KeysDefnitions):
    _dict: Dict[str, BaseSecretKeyDefinition]

    def __init__(self) -> None:
        self._dict = {}

    def get(self, key_name: str) -> BaseSecretKeyDefinition:
        return self._dict.get(key_name)

    def set(self, key_name: str, definition: BaseSecretKeyDefinition) -> None:
        self._dict[key_name] = definition

    def get_all_names(self) -> Iterable[str]:
        return self._dict.keys()

    def get_all_definitions(self) -> Iterable[BaseSecretKeyDefinition]:
        return self._dict.values()

    def items(self) -> Iterable[Tuple[str, BaseSecretKeyDefinition]]:
        return self._dict.items()

    def __iter__(self) -> Iterator[str]:
        return self._dict.__iter__()

    def __contains__(self, key_name: str) -> bool:
        return self._dict.__contains__(key_name)

    def __getitem__(self, key_name: str) -> BaseSecretKeyDefinition:
        return self._dict.__getitem__(key_name)

    def __setitem__(self, key_name: str, definition: BaseSecretKeyDefinition) -> None:
        self._dict.__setitem__(key_name, definition)







