# -*- coding: utf-8 -*-

"""Console script for digg."""

import click
import digg


@click.command()
def main(args=None):
    digg.main()


if __name__ == "__main__":
    main()
