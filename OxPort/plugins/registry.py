from plugins.anonymous import runner as anonymous_runner
from plugins.banner import runner as banner_runner
from plugins.http_enum import runner as http_enum_runner
from plugins.modbus import runner as modbus_runner

MODULES = {
    "anonymous": anonymous_runner,
    "banner": banner_runner,
    "http_enum": http_enum_runner,
    "modbus": modbus_runner,
}


def get_module(name: str):
    return MODULES.get(name.lower())


def list_modules():
    return sorted(MODULES.keys())