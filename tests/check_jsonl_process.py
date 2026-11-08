"""A5 standalone-process checks; Python standard library only, no network."""
import json
import pathlib
import resource
import subprocess
import sys
import tempfile


def limit_file_size():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    fixtures = pathlib.Path(sys.argv[2]).resolve()
    rules = str(pathlib.Path(sys.argv[3]).resolve())
    command = [binary, "--mode", "pcap", "--input", str(fixtures / "jsonl_pipeline.pcap"),
               "--rules", rules, "--max-flows", "1", "--tcp-stream-bytes", "16"]
    result = subprocess.run(command + ["--log", "-"], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert {row["event_type"] for row in rows} == {
        "alert", "verdict", "flow", "parse_error", "reassembly_warning", "stats", "engine_error"}
    assert rows[-1]["packets_total"] == 10
    assert rows[-1]["detections"] == 2
    assert rows[-1]["rule_matches_emitted"] == 3
    expected_drops = rows[-1]["simulated_drop_packets"]
    assert expected_drops == 3  # retransmission and conflicting retransmission keep first-seen Drop
    assert rows[-1]["log_events_written"] == len(rows)
    assert b"log_complete=1" in result.stderr
    with tempfile.TemporaryDirectory(prefix="miniips-a5-process-") as directory:
        log = pathlib.Path(directory) / "events.jsonl"
        result = subprocess.run(command + ["--log", str(log)], capture_output=True, check=False)
        assert result.returncode == 0, result.stderr
        before = log.read_bytes()
        assert log.stat().st_mode & 0o777 == 0o600
        result = subprocess.run(command + ["--log", str(log)], capture_output=True, check=False)
        assert result.returncode == 1 and log.read_bytes() == before
        for destination in ("-", str(pathlib.Path(directory) / "limited-file.jsonl")):
            captured = pathlib.Path(directory) / "limited-stdout.jsonl"
            if destination == "-":
                with captured.open("wb") as output:
                    result = subprocess.run(command + ["--log", destination], stdout=output,
                                            stderr=subprocess.PIPE, check=False,
                                            preexec_fn=limit_file_size)
                diagnostic = result.stderr + captured.read_bytes()
            else:
                result = subprocess.run(command + ["--log", destination], capture_output=True,
                                        check=False, preexec_fn=limit_file_size)
                diagnostic = result.stderr + result.stdout
            assert result.returncode == 1, (destination, result.returncode, diagnostic)
            assert b"packets=10 parsed=9 skipped=1" in diagnostic, diagnostic
            assert f"simulated_drops={expected_drops}".encode() in diagnostic, diagnostic
            assert b"log_complete=0" in result.stderr, diagnostic
    result = subprocess.run([binary, "--mode", "pcap", "--input", str(fixtures / "truncated.pcap"),
                             "--log", "-"], capture_output=True, check=False)
    assert result.returncode == 1
    assert not json.loads(result.stdout.splitlines()[-1])["capture_complete"]
    # Parent closes the read end before consuming output. Child starts with
    # ordinary SIGPIPE disposition (Popen restore_signals=True is the default).
    process = subprocess.Popen(command + ["--log", "-"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    process.stdout.close()
    diagnostic = process.stderr.read()
    process.stderr.close()
    code = process.wait(timeout=15)
    assert code == 1, (code, diagnostic)
    assert b"packets=10 parsed=9 skipped=1" in diagnostic, diagnostic
    assert f"simulated_drops={expected_drops}".encode() in diagnostic, diagnostic
    assert b"log_complete=0" in diagnostic, diagnostic
    print(json.dumps({"cases": 7, "failed": 0, "stdout_rows": len(rows),
                      "broken_pipe_exit": code, "log_permissions": "0600"}))


if __name__ == "__main__":
    main()
