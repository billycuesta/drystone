import logging

from drystone.utils.logging import setup_file_logging


def test_setup_file_logging_replaces_previous_session_file_handler(tmp_path):
    first_log = tmp_path / "session-1" / "audit.log"
    second_log = tmp_path / "session-2" / "audit.log"
    logger = logging.getLogger("drystone")

    # Preserve non-Drystone handlers but start with no session file handlers.
    for handler in list(logger.handlers):
        if getattr(handler, "_drystone_session_file_handler", False):
            logger.removeHandler(handler)
            handler.close()

    setup_file_logging(first_log)
    logger.info("first only")

    setup_file_logging(second_log)
    logger.info("second only")

    first_text = first_log.read_text()
    second_text = second_log.read_text()

    assert "first only" in first_text
    assert "second only" not in first_text
    assert "second only" in second_text


def test_setup_file_logging_is_idempotent_for_same_path(tmp_path):
    log_path = tmp_path / "session" / "audit.log"
    logger = logging.getLogger("drystone")

    for handler in list(logger.handlers):
        if getattr(handler, "_drystone_session_file_handler", False):
            logger.removeHandler(handler)
            handler.close()

    setup_file_logging(log_path)
    setup_file_logging(log_path)

    session_handlers = [
        handler
        for handler in logger.handlers
        if getattr(handler, "_drystone_session_file_handler", False)
    ]
    assert len(session_handlers) == 1
