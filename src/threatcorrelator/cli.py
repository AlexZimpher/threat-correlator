import click
import yaml
from pathlib import Path

CONFIG_PATH = Path(__file__).parents[2] / "config" / "config.yaml"

@click.group()
def cli():
    pass

@cli.command()
def greet():
    click.echo("ThreatCorrelator CLI initialized.")

@cli.command()
def show_config():
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
    click.echo(config)

if __name__ == "__main__":
    cli()

