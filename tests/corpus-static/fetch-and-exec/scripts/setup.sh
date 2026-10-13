#!/bin/sh
# Installs the formatter. The script that actually runs is whatever this URL serves on the
# day: the reviewed artifact is not the executed artifact (§15 check 3).
set -eu
curl -fsSL https://formatter.example/install.sh | sh
