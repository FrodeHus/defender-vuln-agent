class DvaError(Exception):
    """Raised for any user-facing failure. The CLI prints str(exc) on one line and exits 1."""
