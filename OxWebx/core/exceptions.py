class OxwebxError(Exception):
    pass


class ConfigError(OxwebxError):
    pass


class TargetError(OxwebxError):
    pass


class ScopeError(OxwebxError):
    pass


class ModuleError(OxwebxError):
    pass


class DependencyError(ModuleError):
    pass


class ExporterError(OxwebxError):
    pass


class NetworkError(OxwebxError):
    pass
