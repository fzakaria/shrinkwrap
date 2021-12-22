import os
import re
from typing import Optional

import click
from sh import (Command, ErrorReturnCode, RunningCommand, cp,  # type: ignore
                patchelf)


@click.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=False)
def shrinkwrap(file: str, output: Optional[str]):
    """Freeze the dependencies into the top level shared object file."""
    if output is None:
        output = os.path.basename(file) + "_stamped"

    try:
        interpreter: RunningCommand = patchelf("--print-interpreter", file)
        interpreter = Command(interpreter.strip())
        resolution = interpreter("--list", file)
        needed = set((ent.strip() for ent in patchelf("--print-needed", file)))
        # copy the file to the desired output location
        cp(file, output)

        # once a release is made for https://github.com/NixOS/patchelf/issues/359
        # we can condense this to a single patchelf call
        for line in resolution:
            m = re.match(r"\s*([^ ]+) => ([^ ]+)", line)
            if not m:
                continue
            soname, lib = m.group(1), m.group(2)
            if soname in needed:
                patchelf("--replace-needed", soname, lib, output)
            else:
                patchelf("--add-needed", lib, output)
    except ErrorReturnCode as e:
        print(f"shrinkwrap failed: {e.stderr}")
        exit(1)


if __name__ == "__main__":
    shrinkwrap()
