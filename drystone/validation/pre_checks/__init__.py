# ruff: noqa
"""Compatibility facade for deterministic pre-checks.

This package preserves the public API of the former
``drystone.validation.pre_checks`` module while splitting implementation by
core/metadata/helpers and per-skill modules.
"""

from .core import (
    PRE_CHECK_REGISTRY,
    PreCheckFn,
    PreCheckResult,
    _register,
    format_pre_checks_for_prompt,
    run_pre_checks,
)
from .metadata import (
    PRE_CHECK_ANALOGIES,
    PRE_CHECK_DESCRIPTIONS,
    PRE_CHECK_IMPACTS,
    PRE_CHECK_REMEDIATIONS,
)
from .helpers import *

# Import skill modules in the original monolithic file order so decorator-based
# registry population remains stable.
from .iam import *
from .hardening import *
from .alerting import *
from .exposure import *
from .network import *
from .waf import *
from .vulns import *
from .secretsmanager import *
from .ecr import *
from .kms import *
from .messaging import *
from .cicd import *
from .compute import *
from .recon import *
from .sistemas_explotables_red import *
from .cloudtrail_events import *

__all__ = [name for name in globals() if not name.startswith("__")]
