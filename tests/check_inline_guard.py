"""Run real script rejection paths with only fake ip/nft executables visible."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    if sys.flags.optimize:
        raise RuntimeError("Run guard checks without optimization")
    script = pathlib.Path(sys.argv[1]).resolve()
    if not script.is_file():
        raise RuntimeError("Inline test script missing")
    current = os.readlink("/proc/self/ns/net")
    with tempfile.TemporaryDirectory(prefix="miniips-a7-guard-") as directory:
        root = pathlib.Path(directory)
        for name in ("ip", "nft"):
            tool = root / name
            tool.write_text('#!/bin/sh\nprintf called > "$MINIIPS_A7_GUARD_MARKER"\nexit 73\n')
            tool.chmod(0o700)
        for mode, token in (("flag", current), ("none", current), ("env", current), ("flag", "net:[999999999999]")):
            marker = root / "called"
            environment = os.environ.copy()
            environment.pop("PYTHONOPTIMIZE", None)
            environment.update(PATH=str(root), MINIIPS_A7_HOST_NETNS=token, MINIIPS_A7_GUARD_MARKER=str(marker))
            if mode == "env":
                environment["PYTHONOPTIMIZE"] = "1"
            command = [sys.executable] + (["-O"] if mode == "flag" else [])
            result = subprocess.run(command + [str(script), "unused", "unused", str(root / "nft")],
                                    env=environment, capture_output=True, timeout=10, check=False)
            assert result.returncode != 0, result.stdout
            assert not marker.exists(), "network command reached before rejection"
            expected = b"fresh netns" if mode == "none" else b"optimized Python"
            assert expected in result.stderr, result.stderr
    print(json.dumps({"cases": 4, "failed": 0, "real_network_commands": 0}))


if __name__ == "__main__":
    main()
