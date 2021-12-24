from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Dict

import lief  # type: ignore
from sh import Command  # type: ignore


class LinkStrategy(ABC):
    @staticmethod
    def select_by_name(name: str) -> LinkStrategy:
        if name == "native":
            return NativeLinkStrategy()
        elif name == "virtual":
            return VirtualLinkStrategy()
        else:
            raise Exception(f"Unknown strategy: {name}")

    @abstractmethod
    def explore(self, binary: lief.Binary, filename: str) -> Dict[str, str]:
        """
        Determine the linking for all needed objects
        """
        pass


class NativeLinkStrategy(LinkStrategy):
    """Uses the native interpreter in the binary to determine the linking"""

    def explore(self, binary: lief.Binary, filename: str) -> Dict[str, str]:
        interpreter = Command(binary.interpreter)
        resolution = interpreter("--list", filename)
        result = {}
        for line in resolution:
            m = re.match(r"\s*([^ ]+) => ([^ ]+)", line)
            if not m:
                continue
            soname, lib = m.group(1), m.group(2)
            result[soname] = lib
        return result


class VirtualLinkStrategy(LinkStrategy):
    def explore(self, binary: lief.Binary, filename: str) -> Dict[str, str]:
        """
        Determine the linking for all needed objects
        """
        raise Exception("Unimplemented")
