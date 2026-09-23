from drystone.reports.formats.base import BaseFormatter
from drystone.reports.formats.markdown import MarkdownFormatter
from drystone.reports.formats.pdf import PDFFormatter


def test_evidence_file_labels_singleton_identity():
    """Assert the three formatters share the identical _EVIDENCE_FILE_LABELS object.

    This verifies we removed duplicate dictionaries and rely on the BaseFormatter
    canonical map (identity check, not just equality).
    """
    assert MarkdownFormatter._EVIDENCE_FILE_LABELS is PDFFormatter._EVIDENCE_FILE_LABELS is BaseFormatter._EVIDENCE_FILE_LABELS
