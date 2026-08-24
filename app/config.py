DATABASE_URL = "sqlite:///./vulntracker.db"

SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials (migrate to env vars before production deployment)
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"

# Internal service API key
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"

NOTIFY_SERVICE_URL = "http://localhost:3001"

# Hosts this API will accept requests for (enforced via TrustedHostMiddleware).
# Prevents Host-header spoofing from being reflected back into generated URLs
# (e.g. the share_url returned by POST /scans/{id}/share). Extend/override this
# list with the real public domain(s) per deployment environment.
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
