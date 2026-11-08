"""Explicit privileged A6 checks, confined to a fresh anonymous netns.

Usage: MINIIPS_A6_HOST_NETNS=$(readlink /proc/self/ns/net) unshare --net -- \
       python3 tests/check_live_process.py build/miniips build/tests/fixtures rules/a5-demo.json
"""
import json
import os
import pathlib
import resource
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def limited_file():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))


def main():
    if sys.flags.optimize:
        raise RuntimeError("Live verification forbids optimized Python; assertions must remain enabled")
    parent_ns = os.environ.get("MINIIPS_A6_HOST_NETNS")
    if not parent_ns or parent_ns == os.readlink("/proc/self/ns/net"):
        raise RuntimeError("Run in a fresh netns; host changes forbidden")
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    fixtures = pathlib.Path(sys.argv[2]).resolve()
    rules = str(pathlib.Path(sys.argv[3]).resolve())
    subprocess.run(["ip", "link", "add", "a6cap", "type", "veth", "peer", "name", "a6send"], check=True)
    for device in ("a6cap", "a6send"):
        subprocess.run(["ip", "link", "set", device, "addrgenmode", "none"], check=True)
        subprocess.run(["ip", "link", "set", device, "up"], check=True)
    address = json.loads(subprocess.check_output(["ip", "-j", "link", "show", "a6cap"]))[0]["address"]
    destination = bytes.fromhex(address.replace(":", ""))
    data = (fixtures / "jsonl_pipeline.pcap").read_bytes()
    frames = []
    offset = 24
    while offset < len(data):
        _, _, captured, _ = struct.unpack_from("<IIII", data, offset)
        offset += 16
        frame = data[offset:offset + captured]
        offset += captured
        if len(frame) < 14:
            frame = b"\0" * 12 + b"\x08\x00"
        frames.append(destination + frame[6:])
    assert len(frames) == 10
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sender.bind(("a6send", 0))
    base = [binary, "--mode", "live", "--interface", "a6cap", "--rules", rules,
            "--max-flows", "1", "--tcp-stream-bytes", "16"]
    cases = []

    def start(extra, **kwargs):
        return subprocess.Popen(base + extra, stdout=kwargs.pop("stdout", subprocess.PIPE),
                                stderr=subprocess.PIPE, bufsize=0, **kwargs)

    def ready(process):
        assert process.stderr is not None
        deadline = time.monotonic() + 10
        with selectors.DefaultSelector() as poll:
            poll.register(process.stderr, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if poll.select(0.2):
                    line = process.stderr.readline()
                    if b"live_ready " in line:
                        return
                    if not line:
                        break
        process.kill()
        out, err = process.communicate(timeout=5)
        raise AssertionError(("live_ready missing", process.returncode, out, err))

    def send():
        for frame in frames:
            sender.send(frame)
            time.sleep(0.01)

    def finish(process):
        try:
            return process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise AssertionError("live process did not stop")

    def parse(output):
        return [json.loads(line) for line in output.splitlines()]

    def check_stats(output, reason):
        rows = parse(output)
        assert rows and all(row["mode"] == "live" and not row["enforced"] for row in rows)
        stats = rows[-1]
        assert stats["event_type"] == "stats"
        assert stats["run_complete"] and not stats["capture_complete"]
        assert stats["stop_reason"] == reason
        assert stats["actual_drop_packets"] == 0
        assert stats["tcp_memory_bytes"] == stats["rule_state_bytes"] == 0
        assert stats["capture_stats"]["status"] == "available"
        assert stats["capture_stats"]["ifdrop_availability"] == "platform_dependent"
        assert "log_complete" not in stats
        return rows, stats

    process = start(["--packet-count", "10", "--log", "-"])
    ready(process)
    send()
    output, diagnostic = finish(process)
    assert process.returncode == 0, diagnostic
    rows, stats = check_stats(output, "packet_limit")
    assert stats["packets_total"] == 10 and stats["packets_parsed"] == 9
    assert stats["simulated_drop_packets"] == 3 and stats["detections"] == 2
    assert {row["event_type"] for row in rows} == {
        "alert", "verdict", "flow", "parse_error", "reassembly_warning", "engine_error", "stats"}
    assert any(row.get("reason") == "stopped" for row in rows)
    if len(sys.argv) > 4:
        with pathlib.Path(sys.argv[4]).open("xb") as trace:
            trace.write(output)
    cases.append("packet_limit_full_pipeline")

    for number, reason in ((signal.SIGINT, "sigint"), (signal.SIGTERM, "sigterm")):
        process = start(["--log", "-"])
        ready(process)
        process.send_signal(number)
        output, diagnostic = finish(process)
        assert process.returncode == 0, diagnostic
        _, stats = check_stats(output, reason)
        assert stats["packets_total"] == 0 and stats["timestamp"] is None
        cases.append("idle_" + reason)

    process = start(["--log", "-"])
    ready(process)
    send()
    process.send_signal(signal.SIGINT)
    output, diagnostic = finish(process)
    assert process.returncode == 0, diagnostic
    _, stats = check_stats(output, "sigint")
    assert stats["packets_total"] > 0
    cases.append("active_sigint")

    process = start(["--packet-count", "10", "--log", "-"])
    assert process.stdout is not None
    process.stdout.close()
    process.stdout = None
    ready(process)
    send()
    _, diagnostic = finish(process)
    assert process.returncode == 1, diagnostic
    assert b"live_summary packets=10 parsed=9 skipped=1" in diagnostic, diagnostic
    assert b"simulated_drops=3" in diagnostic and b"log_complete=0" in diagnostic
    assert diagnostic.count(b"log_error:") == 1
    cases.append("closed_stdout_continues")

    with tempfile.TemporaryDirectory(prefix="miniips-a6-") as directory:
        for target in ("-", str(pathlib.Path(directory) / "limited-log.jsonl")):
            captured = pathlib.Path(directory) / "limited-stdout"
            if target == "-":
                with captured.open("wb") as destination_file:
                    process = start(["--packet-count", "10", "--log", target],
                                    stdout=destination_file, preexec_fn=limited_file)
                    ready(process)
                    send()
                    output, diagnostic = finish(process)
                combined = diagnostic + captured.read_bytes()
            else:
                process = start(["--packet-count", "10", "--log", target], preexec_fn=limited_file)
                ready(process)
                send()
                output, diagnostic = finish(process)
                combined = output + diagnostic
            assert process.returncode == 1, combined
            assert b"packets=10 parsed=9 skipped=1" in combined, combined
            assert b"simulated_drops=3" in combined and b"log_complete=0" in diagnostic
            assert diagnostic.count(b"log_error:") == 1
            cases.append("file_limit_" + ("stdout" if target == "-" else "owned_log"))

        log = pathlib.Path(directory) / "healthy.jsonl"
        process = start(["--packet-count", "10", "--log", str(log)])
        ready(process)
        send()
        output, diagnostic = finish(process)
        assert process.returncode == 0, diagnostic
        check_stats(log.read_bytes(), "packet_limit")
        assert log.stat().st_mode & 0o777 == 0o600
        before = log.read_bytes()
        result = subprocess.run(base + ["--log", str(log)], capture_output=True, timeout=10, check=False)
        assert result.returncode == 1 and log.read_bytes() == before
        cases.append("new_file_0600_and_preservation")

    for device in ("no_such_ids0", "any"):
        args = base.copy()
        args[args.index("a6cap")] = device
        result = subprocess.run(args + ["--log", "-"], capture_output=True, timeout=10, check=False)
        assert result.returncode == 1
        errors = parse(result.stdout)
        assert errors[0]["event_type"] == "engine_error" and errors[0]["mode"] == "live"
        assert not errors[-1]["run_complete"]
        cases.append("rejected_device_" + device)
    result = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + base + ["--log", "-"],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 1, result.stderr
    assert parse(result.stdout)[-1]["capture_stats"]["status"] == "not_open"
    cases.append("capture_permission_denied")
    sender.close()
    print(json.dumps({"cases": len(cases), "failed": 0, "names": cases,
                      "packet_limit_processed": 10, "detections": 2, "simulated_drops": 3,
                      "actual_drop_packets": 0, "isolated": True}))


if __name__ == "__main__":
    main()
