from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .secret_key_use_case import SecretKeyUseCase
    from .types import SecretKeyPairValues


class SecretKeyState(ABC):
    @abstractmethod
    def get_last_use_case(self) -> SecretKeyUseCase:
        pass

    @abstractmethod
    def set_last_use_case(self, last_use: SecretKeyUseCase) -> None:
        pass

    @abstractmethod
    def get_previous_keys(self) -> SecretKeyPairValues:
        pass

    @abstractmethod
    def set_previous_keys(self, keys: SecretKeyPairValues):
        pass

    @abstractmethod
    def clean_state(self) -> None:
        pass
