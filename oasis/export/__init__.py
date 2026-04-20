"""
Report export helpers.

Import submodules directly (e.g. ``from oasis.export.vulnerability import write_vulnerability_artifacts``)
so environments without WeasyPrint can still use ``oasis.export.filenames`` / ``oasis.export.sarif``.

Multi-artifact writers return :class:`~oasis.export.result_types.ArtifactWriteStatusMap`
(see ``oasis.export.result_types``).
"""

from .filenames import artifact_filename
from .result_types import ArtifactWriteStatusMap

__all__ = ["artifact_filename", "ArtifactWriteStatusMap"]
