#!/bin/bash
#
# Build wrapper that runs make.sh before building the package
#

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "==> Running pre-build script: tools/prompt/make/make.sh"
if [ -f "tools/prompt/make/make.sh" ]; then
    bash tools/prompt/make/make.sh
    echo "==> Pre-build script completed"
else
    echo "Warning: tools/prompt/make/make.sh not found, skipping"
fi

# echo "==> Building Python package"
# python -m build

# echo "==> Build complete"