from typing import Optional

import click


@click.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path())
def shrinkwrap(file: str, output: Optional[str]):
    """Emboss the dependencies into the top level shared object file."""
    click.echo(f"Hello {type(output)}!")


if __name__ == "__main__":
    shrinkwrap()
