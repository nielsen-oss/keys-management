from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from .secret_key import SecretKeyPair, SecretKeyValue
    from .secret_key_use_case import SecretKeyFlow, SecretKeyUseCase
    from .types import StrOrBytes, StrOrBytesPair


class SecretKeyState(ABC):
    @abstractmethod
    def get_last_flow(self) -> Optional[SecretKeyFlow]:
        pass

    @abstractmethod
    def set_last_flow(self, last_use: SecretKeyFlow) -> None:
        pass

    @abstractmethod
    def get_previous_keys(self) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        pass

    @abstractmethod
    def set_previous_keys(self, keys: Union[StrOrBytes, StrOrBytesPair]) -> None:
        pass

    @abstractmethod
    def clean_state(self) -> None:
        pass
