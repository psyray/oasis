"""Assistant prompt, tuning, character budgets, shrink, and report excerpt.

Verdict-assembly and validation bridge re-exports live in
:mod:`oasis.helpers.assistant.prompt.chat_context` (not imported from this package: avoids a
circular import with :mod:`oasis.helpers.assistant.verdict` during submodule loads).

Public names are declared only via each leaf module's ``__all__`` merged below—add new symbols on
the leaf modules first, then this list stays mechanically in sync without a second handwritten set.
"""

from __future__ import annotations

from . import context_budget
from . import prompt_shrink
from . import prompt_tuning
from . import report_excerpt

# Re-exports: do not add ``chat_context`` here (it imports ``verdict`` while ``verdict`` may
# still be loading ``verdict_assembly`` which imports ``prompt_shrink`` from this package).
from .context_budget import *  # noqa: F401,F403
from .prompt_shrink import *  # noqa: F401,F403
from .prompt_tuning import *  # noqa: F401,F403
from .report_excerpt import *  # noqa: F401,F403

__all__ = sorted(
    {
        *context_budget.__all__,
        *prompt_shrink.__all__,
        *prompt_tuning.__all__,
        *report_excerpt.__all__,
    }
)
