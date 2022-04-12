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
    needed = list(binary.libraries)
    for name in needed:
        binary.remove_library(name)

    for soname, lib in reversed(resolution.items()):
        print(soname, lib)
        binary.add_library(lib)

    # we need to update the VERNEED entries now to match
    verneeded = binary.symbols_version_requirement
    for verneed in verneeded:
        if verneed.name in resolution:
            # we want to map the possible shortname soname
            # to the absolute one we generate
            verneed.name = resolution.get(verneed.name)

    # dump the new binary file
    binary.write(output)

    # copy the file metadata
    copystat(file, output)


if __name__ == "__main__":
    shrinkwrap()
