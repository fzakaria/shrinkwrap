import functools
from glob import glob
from os.path import abspath, dirname, isabs, join
from typing import Set


# source: https://gist.github.com/stuaxo/79bcdcbaf9aa3b277207
@functools.lru_cache()
def parse(filename: str = "/etc/ld.so.conf") -> Set[str]:
    """Load all the paths from a given ldso config file"""
    paths = set()
    directory = dirname(abspath(filename))
    with open(filename) as f:
        for line in (_line.rstrip() for _line in f.readlines()):
            if line.startswith("include "):
                wildcard = line.partition("include ")[-1:][0].rstrip()
                if not isabs(wildcard):
                    wildcard = join(directory, wildcard)
                for filename in glob(wildcard):
                    paths |= parse(filename)
            elif not line.startswith("#"):
                if line:
                    paths.add(line)
    return paths
