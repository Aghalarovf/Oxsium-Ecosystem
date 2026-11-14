from __future__ import annotations

import argparse

from core.modules import SCAN_ORDER


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oxad.py")

    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument("-i", "--ip", required=True)
    conn_group.add_argument("-d", "--domain", required=True)
    conn_group.add_argument("-u", "--username", default="")
    conn_group.add_argument("--dc-host", default=None)
    conn_group.add_argument("--use-ssl", action="store_true")

    auth_group = parser.add_argument_group("authentication")
    cred_group = auth_group.add_mutually_exclusive_group()
    cred_group.add_argument("-p", "--password", default="")
    cred_group.add_argument("--hash", dest="nt_hash", default=None)
    cred_group.add_argument("--ccache", default=None)

    scan_group = parser.add_argument_group("scan")
    scan_group.add_argument(
        "-m",
        "--modules",
        nargs="+",
        choices=SCAN_ORDER + ["all"],
        default=["all"],
    )

    scan_group.add_argument("--enumerate-ip", action="store_true")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("--output-dir", default=None)
    output_group.add_argument("-v", "--verbose", action="store_true")

    return parser


def parse(argv=None) -> argparse.Namespace:
    return build_parser().parse_args(argv)