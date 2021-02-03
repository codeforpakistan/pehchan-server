#!/bin/bash

export URLS_SELF_ISSUER=http://127.0.0.1:5000
export URLS_CONSENT=http://127.0.0.1:5002/consent
export URLS_LOGIN=http://127.0.0.1:5002/login
export URLS_LOGOUT=http://127.0.0.1:5002/logout
export SECRETS_SYSTEM=youReallyNeedToChangeThis
export OIDC_SUBJECT_IDENTIFIERS_SUPPORTED_TYPES=public,pairwise
export OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT=youReallyNeedToChangeThis
export SERVE_PUBLIC_CORS_ENABLED=true
export SERVE_PUBLIC_CORS_ALLOWED_METHODS=POST,GET,PUT,DELETE
export SERVE_ADMIN_CORS_ENABLED=true
export SERVE_ADMIN_CORS_ALLOWED_METHODS=POST,GET,PUT,DELETE
export LOG_LEVEL=trace
export OAUTH2_EXPOSE_INTERNAL_ERRORS=1
export SERVE_PUBLIC_PORT=5000
export SERVE_ADMIN_PORT=5001
export LOG_LEAK_SENSITIVE_VALUES=true
