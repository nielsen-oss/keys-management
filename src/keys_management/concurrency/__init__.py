from __future__ import annotations
from typing import Union
from enum import Enum
from abc import ABC, abstractmethod
import threading
import multiprocessing
from contextlib import contextmanager


class Synchronizer(object):

    @contextmanager
    def read(self) -> ContextManager:
        try:
            yield self.acquire_read()
        finally:
            self.release_read()

    @contextmanager
    def write(self) -> ContextManager:
        try:
            yield self.acquire_write()
        finally:
            self.release_write()

    def acquire_read(self) -> bool:
        raise NotImplementedError()

    def release_read(self):
        raise NotImplementedError()

    def acquire_write(self) -> bool:
        raise NotImplementedError()

    def release_write(self):
        raise NotImplementedError()

    def is_locked_read(self) -> bool:
        raise NotImplementedError()

    def is_locked_write(self) -> bool:
        raise NotImplementedError()


class StubLock:
    def acquire(self) -> bool:
        return True

    def release(self) -> None:
        pass

    def locked(self) -> bool:
        return False


class DefaultSynchronizer(Synchronizer):
    _lock: Union[threading.Lock, multiprocessing.synchronize.Lock, StubLock]

    def __init__(self, lock: Union[threading.Lock, multiprocessing.synchronize.Lock, StubLock]  ) -> None:
        self._lock = lock

    def acquire_read(self) -> bool:
        return self._lock.acquire()

    def release_read(self):
        self._lock.release()

    def acquire_write(self) -> bool:
        return self._lock.acquire()

    def release_write(self):
        self._lock.release()

    def is_locked_read(self) -> bool:
        return self._lock.locked()

    def is_locked_write(self) -> bool:
        return self._lock.locked()


class SynchronizerFactory:
    def create(self) -> ReadWriteSynchronizer:
        raise NotImplementedError()

    def __ceil__(self) -> ReadWriteSynchronizer:
        return self.create()


class EnvironemtType:
    SINGLE = 1
    MULTITHREADED = 2
    MULTIPROCESS = 3


class DefaultSynchronizerFactory:
    _environemt_type: EnvironemtType

    def __init__(self, environemt_type: EnvironemtType) -> None:
      self._environemt_type: EnvironemtType = environemt_type

    def create(self) -> Synchronizer:
        if self._environemt_type == EnvironemtType.SINGLE:
            return DefaultSynchronizer(StubLock())
        elif self._environemt_type == EnvironemtType.MULTITHREADED:
            return DefaultSynchronizer(threading.Lock())
        else:
            return DefaultSynchronizer(multiprocessing.Lock())

    def __ceil__(self) -> ReadWriteSynchronizer:
        return self.create()