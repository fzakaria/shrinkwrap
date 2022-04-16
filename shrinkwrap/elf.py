from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Dict, Iterable, Optional

import lief  # type: ignore
from sh import Command  # type: ignore

from shrinkwrap import ldsoconf


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
        result = OrderedDict()
        # TODO: Figure out why `--list` and `ldd` produce different outcomes
        # specifically for the interpreter.
        # https://gist.github.com/fzakaria/3dc42a039401598d8e0fdbc57f5e7eae
        for line in resolution:
            m = re.match(r"\s*([^ ]+) => ([^ ]+)", line)
            if not m:
                continue
            soname, lib = m.group(1), m.group(2)
            result[soname] = lib
        return result


class VirtualLinkStrategy(LinkStrategy):

    # TODO: Need to figure out a good way to determine the NEEDED of glibc
    # I think it's resolving based on a shared object cache from the .INTERP
    # section but that remains to be validated.
    SKIP = ["ld-linux.so.2", "ld-linux-x86-64.so.2"]

    @staticmethod
    def find(
        paths: Iterable[str],
        soname: str,
        identity_class: lief.ELF.ELF_CLASS,
        machine_type: lief.ELF.ARCH,
    ) -> Optional[str]:
        """Given a list of paths, try and find it. It does not search recursively"""
        for path in paths:
            full_path = os.path.join(path, soname)
            if os.path.exists(full_path):
                if not lief.is_elf(full_path):
                    continue
                binary = lief.parse(full_path)
                if (
                    binary.header.identity_class != identity_class
                    or binary.header.machine_type != machine_type
                ):
                    continue
                return full_path
        return None

    @staticmethod
    def has_nodeflib(binary: lief.Binary) -> bool:
        if not binary.has(lief.ELF.DYNAMIC_TAGS.FLAGS_1):
            return False
        for flag in binary[lief.ELF.DYNAMIC_TAGS.FLAGS_1].flags:
            if flag == lief.ELF.DYNAMIC_FLAGS_1.NODEFLIB:
                return True
        return False

    def explore(self, binary: lief.Binary, filename: str) -> Dict[str, str]:
        """
        Determine the linking for all needed objects
        """

        result = OrderedDict()
        queue = [binary]
        rpaths = []
        ld_library_path = os.environ.get("LD_LIBRARY_PATH", "").split(":")
        default_paths = ldsoconf.parse()
        seen = set()

        # The following is a rough translation of the search as described in
        # https://man7.org/linux/man-pages/man8/ld.so.8.html
        # 1. IF RUNPATH is not present, and RPATH is present use RPATH.
        #    Note: RPATH is cumaltive as it traverses the children
        # 2. Use the environment variable LD_LIBRARY_PATH
        # 3. Use RUNPATH to locate only the current shared objects dependencies
        # 4. Default libraries, unless ELF file has 'nodeflibs' set
        while len(queue) > 0:
            current = queue.pop()

            if current.has(lief.ELF.DYNAMIC_TAGS.RPATH):
                rpaths += current.get(lief.ELF.DYNAMIC_TAGS.RPATH).paths

            runpaths = []
            if current.has(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                runpaths += current.get(lief.ELF.DYNAMIC_TAGS.RUNPATH).paths

            needed = current.libraries

            # any binaries found need to make sure we match
            # the identity_class and machine_type
            identity_class = current.header.identity_class
            machine_type = current.header.machine_type

            for soname in needed:

                if soname in VirtualLinkStrategy.SKIP:
                    continue

                if os.path.basename(soname) in seen:
                    continue

                path = None
                # IF RUNPATH is not present, and RPATH is present use RPATH.
                if not path and len(runpaths) == 0 and len(rpaths) > 0:
                    path = VirtualLinkStrategy.find(
                        rpaths, soname, identity_class, machine_type
                    )
                # Use the environment variable LD_LIBRARY_PATH
                if not path and len(ld_library_path) > 0:
                    path = VirtualLinkStrategy.find(
                        ld_library_path, soname, identity_class, machine_type
                    )
                    if path:
                        result[soname] = path

                # Use RUNPATH to locate only the current shared objects dependencies
                if not path and len(runpaths) > 0:
                    path = VirtualLinkStrategy.find(
                        runpaths, soname, identity_class, machine_type
                    )

                if not path and not VirtualLinkStrategy.has_nodeflib(current):
                    path = VirtualLinkStrategy.find(
                        default_paths, soname, identity_class, machine_type
                    )

                if not path:
                    raise Exception(f"Could not find {soname}")

                # lets add the basename of the soname to a cache
                # so that any object that requires the same soname is skipped
                # this works since this is the same behavior as in glibc
                seen.add(os.path.basename(soname))

                result[soname] = path
                queue.append(lief.parse(path))

        return result
