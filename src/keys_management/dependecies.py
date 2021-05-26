from typing import Any, Dict


class StateRepoInterface(object):
    def write_state(self, key: str, key_state: Any) -> None:
        raise NotImplementedError()

    def read_state(self, key: str) -> Dict:
        raise NotImplementedError()


class CryptoTool(object):
    def encrypt(self, data: Any) -> Any:
        raise NotImplementedError()

    def decrypt(self, encrypted_data: Any) -> Any:
        raise NotImplementedError()
