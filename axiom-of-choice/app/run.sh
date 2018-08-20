#!/bin/sh

WORKERS=10
TIMEOUT=10

gunicorn                    \
    --bind 0.0.0.0:8081     \
    --workers $WORKERS      \
    --timeout $TIMEOUT      \
    app:app
