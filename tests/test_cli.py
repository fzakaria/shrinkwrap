from click.testing import CliRunner

from shrinkwrap import cli


def test_cli_no_arguments():
    runner = CliRunner()
    result = runner.invoke(cli.shrinkwrap)
    assert result.exit_code == 2


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli.shrinkwrap, ["--help"])
    assert result.exit_code == 0
