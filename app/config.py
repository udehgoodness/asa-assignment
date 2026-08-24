import logging
import os
import secrets

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # No static fallback on purpose (see docs/findings.md VT-03) — a random
    # ephemeral key keeps local dev/CI working with zero setup, at the cost
    # of tokens not surviving a restart or being shared across replicas.
    # Anything beyond local development must set SECRET_KEY explicitly via
    # a secrets manager.
    SECRET_KEY = secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY not set — generated an ephemeral key for this process. "
        "Tokens will not survive a restart and will not be valid across "
        "multiple replicas. Set SECRET_KEY via a secrets manager for any "
        "non-local environment."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Hosts this API will accept requests for (enforced via TrustedHostMiddleware).
# Prevents Host-header spoofing from being reflected back into generated URLs
# (e.g. the share_url returned by POST /scans/{id}/share). Extend/override this
# list with the real public domain(s) per deployment environment.
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
