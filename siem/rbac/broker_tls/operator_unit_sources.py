"""Constrain explicit unit launch sources without starting the Dashboard.

This is a read-only check of selected systemd properties. It excludes a PAM
session, custom executable search path, dynamic user and configured service
directory sources. It reports whether systemd login variables are enabled,
but does not read the manager's own environment, vendor wrapper variables or
the final process environment. It cannot authorize a start. Private property
values stay private.
"""
from dataclasses import dataclass, field

from . import operator_core as core
from . import operator_launch as launch
from . import operator_service as service


def _constrain(config):
    rows = config['ExecStartEx']
    core.require(len(rows) == 1 and rows[0][0] == launch.WRAPPER
                 and rows[0][1] == [launch.WRAPPER] and rows[0][2] == [],
                 'UNIT_SOURCE_EXEC')
    core.require(config['Environment'] == [], 'UNIT_SOURCE_INLINE_ENV')
    core.require(config['EnvironmentFiles'] == [], 'UNIT_SOURCE_ENV_FILE')
    core.require(config['PassEnvironment'] == [], 'UNIT_SOURCE_PASS_ENV')
    core.require(config['UnsetEnvironment'] == [], 'UNIT_SOURCE_UNSET_ENV')
    core.require(config['PAMName'] == '', 'UNIT_SOURCE_PAM')
    core.require(config['ExecSearchPath'] == [], 'UNIT_SOURCE_SEARCH_PATH')
    core.require(config['DynamicUser'] is False, 'UNIT_SOURCE_DYNAMIC_USER')
    core.require(all(config[name] == [] for name in (
        'RuntimeDirectory', 'StateDirectory', 'CacheDirectory',
        'LogsDirectory', 'ConfigurationDirectory')), 'UNIT_SOURCE_DIRECTORIES')
    core.require(config['User'] == 'wazuh-dashboard'
                 and config['Group'] == 'wazuh-dashboard'
                 and config['WorkingDirectory'] == core.BASE.rstrip('/'),
                 'UNIT_SOURCE_IDENTITY')


@dataclass(frozen=True)
class UnitSourcesObservation:
    login_variables_enabled: bool
    exact_wrapper_argv: bool = field(default=True, init=False)
    explicit_unit_environment_empty: bool = field(default=True, init=False)
    pam_session_disabled: bool = field(default=True, init=False)
    exec_search_path_empty: bool = field(default=True, init=False)
    dynamic_user_disabled: bool = field(default=True, init=False)
    directory_environment_sources_empty: bool = field(default=True, init=False)
    passes: int = field(default=2, init=False)
    service_reads: int = field(default=2, init=False)
    manager_inheritance_proven: bool = field(default=False, init=False)
    selected_config_source_proven: bool = field(default=False, init=False)
    effective_environment_proven: bool = field(default=False, init=False)
    startup_authorized: bool = field(default=False, init=False)


def observe_unit_sources():
    """Compare two private manager snapshots and reject explicit alternatives.

    No configured path, command, argument or environment value is opened,
    executed, logged or returned. Equal reads are not an atomic snapshot.
    An inactive loaded service needs no process or credential.
    """
    service._check_tool()
    first = launch._configuration()
    _constrain(first)
    second = launch._configuration()
    _constrain(second)
    core.require(first == second, 'UNIT_SOURCE_CHANGED')
    # With User= set, SetLoginEnvironment=true creates HOME/LOGNAME/SHELL.
    # Reporting that fact is not an effective-environment or startup proof.
    return UnitSourcesObservation(login_variables_enabled=second['SetLoginEnvironment'])
