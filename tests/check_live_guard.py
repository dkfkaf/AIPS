"""Safety regression: deny optimized/host execution before any network command.

The only ip executable visible to each child is a temporary recorder. Even the
known-bad script can only touch that temporary marker, never a network device.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    if sys.flags.optimize:
        raise RuntimeError("Run guard regression without Python optimization")
    script = pathlib.Path(sys.argv[1]).resolve()
    current_ns = os.readlink("/proc/self/ns/net")
    with tempfile.TemporaryDirectory(prefix="miniips-a6-guard-") as directory:
        root = pathlib.Path(directory)
        fake_ip = root / "ip"
        fake_ip.write_text('#!/bin/sh\nprintf called > "$MINIIPS_A6_IP_MARKER"\nexit 73\n')
        fake_ip.chmod(0o700)
        for optimized, token in (("flag", current_ns), ("none", current_ns), ("env", current_ns), ("flag", "net:[999999999999]")):
            marker = root / "called"
            environment = os.environ.copy()
            environment.pop("PYTHONOPTIMIZE", None)
            environment.update(PATH=str(root), MINIIPS_A6_IP_MARKER=str(marker),
                               MINIIPS_A6_HOST_NETNS=token)
            if optimized == "env":
                environment["PYTHONOPTIMIZE"] = "1"
            command = [sys.executable] + (["-O"] if optimized == "flag" else [])
            result = subprocess.run(command + [str(script), "unused", "unused", "unused"],
                                    env=environment, capture_output=True, timeout=10, check=False)
            assert result.returncode != 0, result.stdout
            assert not marker.exists(), ("network command reached before safety rejection", optimized, result.stderr)
    print(json.dumps({"cases": 4, "failed": 0, "host_network_commands": 0}))


if __name__ == "__main__":
    main()
