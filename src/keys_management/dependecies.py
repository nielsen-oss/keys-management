from typing import Any, Dict, Callable, NoReturn, ContextManager
from contextlib import contextmanager

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

import threading
l = threading.Lock
l.acquire()
l.release()


class KeysLocker(object):

    @contextmanager
    def read(self, key_name: str) -> ContextManager:
        try:
            yield self.acquire_read(key_name)
        finally:
            self.realse_read(key_name)

    @contextmanager
    def write(self, key_name: str) -> ContextManager:
        try:
            yield self.acquire_write(key_name)
        finally:
            self.release_write(key_name)

    def write(self) -> ContextManager:
        pass

    def acquire_read(self, key_to_lock: str):
        pass

    def realse_read(self, key_to_unlock: str):
        pass

    def acquire_write(self, key_to_lock: str):
        pass

    def release_write(self, key_to_unlock: str):
        pass

    def is_locked_read(self, key_name) -> bool:
        pass

    def is_locked_write(self, key_name) -> bool:
        pass



