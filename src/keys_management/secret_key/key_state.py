from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from .secret_key import SecretKeyValue, SecretKeyPair
    from .secret_key_use_case import SecretKeyUseCase
    from .types import StrOrBytesPair, StrOrBytes


class SecretKeyState(ABC):
    @abstractmethod
    def get_last_use_case(self) -> Optional[SecretKeyUseCase]:
        pass

    @abstractmethod
    def set_last_use_case(self, last_use: SecretKeyUseCase) -> None:
        pass

    @abstractmethod
    def get_previous_keys(self) -> Optional[Union[SecretKeyValue, SecretKeyPair]]:
        pass

    @abstractmethod
    def set_previous_keys(
        self, keys: Union[StrOrBytes, StrOrBytesPair]
    ) -> None:
        pass

    @abstractmethod
    def clean_state(self) -> None:
        pass
