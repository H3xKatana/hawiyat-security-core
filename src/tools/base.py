# src/tools/base.py
from abc import ABC, abstractmethod

class SecurityToolAdapter(ABC):
    @abstractmethod
    def run_scan(self, target: str) -> dict:
        pass 