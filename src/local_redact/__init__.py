"""local-redact: remove sensitive data from text before you paste it into an LLM."""

__version__ = "0.1.0"

from .engine import Detection, Mapping, detect, detector_ids, load_spec, redact, restore  # noqa: E402

__all__ = ["Detection", "Mapping", "detect", "detector_ids", "load_spec", "redact", "restore", "__version__"]
