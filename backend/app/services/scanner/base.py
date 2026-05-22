
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        pass
