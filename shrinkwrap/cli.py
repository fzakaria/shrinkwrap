import os
from shutil import copystat
from typing import Optional

import click
import lief  # type: ignore

from shrinkwrap.elf import LinkStrategy


@click.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=False)
@click.option(
    "-l",
    "--link-strategy",
    default="native",
    show_default=True,
    type=click.Choice(["native", "virtual"], case_sensitive=True),
)
def shrinkwrap(file: str, output: Optional[str], link_strategy: str):
    """Freeze the dependencies into the top level shared object file."""
    if output is None:
        output = os.path.basename(file) + "_stamped"

    if not lief.is_elf(file):
        click.echo(f"{file} is not elf format")
        exit(1)

    binary: lief.Binary = lief.parse(file)
    if not binary.has_interpreter:
        click.echo("no interpreter set on the binary")
        exit(1)

    strategy = LinkStrategy.select_by_name(link_strategy)
    resolution = strategy.explore(binary, file)
    needed = binary.libraries

    for soname, lib in resolution.items():
        if soname in needed:
            binary.remove_library(soname)
        binary.add_library(lib)

    # dump the new binary file
    binary.write(output)

    # copy the file metadata
    copystat(file, output)


if __name__ == "__main__":
    shrinkwrap()
