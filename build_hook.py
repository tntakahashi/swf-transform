#!/usr/bin/env python
"""
Custom build hook to run tools/prompt/make/make.sh during package build.
"""
import os
import subprocess
import sys
from pathlib import Path


def run_make_script():
    """Execute the make.sh script in tools/prompt/make/."""
    # Get the project root directory
    project_root = Path(__file__).parent.resolve()
    make_script = project_root / "tools" / "prompt" / "make" / "make.sh"
    
    if not make_script.exists():
        print(f"Warning: make.sh not found at {make_script}", file=sys.stderr)
        return
    
    print(f"Running build script: {make_script}")
    
    try:
        # Make sure the script is executable
        make_script.chmod(0o755)
        
        # Run the script from the project root
        result = subprocess.run(
            [str(make_script)],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        print(f"Build script completed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"Error running make.sh: {e}", file=sys.stderr)
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        # Don't fail the build, just warn
        print("Warning: make.sh failed, continuing with build", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error running make.sh: {e}", file=sys.stderr)


if __name__ == "__main__":
    run_make_script()
