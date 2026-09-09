"""Stop nodes launched from one CI workspace's hubd binary."""

import pathlib
import re
import subprocess
import sys


def process_pattern(binary):
    path = pathlib.Path(binary)
    if not path.is_absolute() or path.name != "hubd":
        raise ValueError("expected an absolute path to hubd")
    return "^" + re.escape(str(path)) + "( |$)"


if __name__ == "__main__":
    result = subprocess.run(["pkill", "-f", process_pattern(sys.argv[1])], check=False)
    sys.exit(0 if result.returncode in (0, 1) else result.returncode)
