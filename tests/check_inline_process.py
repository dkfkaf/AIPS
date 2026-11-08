"""Explicit A7 real UDP verdict checks in a fresh anonymous network namespace.

Arguments: binary rules nft [new-trace-path]. Never installs services/rules on host.
"""
import json
import os
import pathlib
import resource
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def limit_file():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))


def main():
    if sys.flags.optimize:
        raise RuntimeError("Inline verification forbids optimized Python")
    host = os.environ.get("MINIIPS_A7_HOST_NETNS")
    if not host or host == os.readlink("/proc/self/ns/net"):
        raise RuntimeError("Inline test requires a fresh netns; host changes forbidden")
    binary, rules, nft = (str(pathlib.Path(value).resolve()) for value in sys.argv[1:4])
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    queue_num, port = 42420, 58427
    table = "miniips_a7"
    subprocess.run([nft, "add", "table", "ip", table], check=True)
    processes = []
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", port))
    server.settimeout(0.4)
    base = [binary, "--mode", "inline", "--queue-num", str(queue_num), "--enable-inline", "--rules", rules]
    cases = []

    class Process:
        def __init__(self, extra, stdout=subprocess.PIPE, closed=False, limited=False, flag_first=False):
            command = base + extra
            if flag_first:
                command.remove("--enable-inline")
                command.insert(1, "--enable-inline")
            self.process = subprocess.Popen(command, stdout=stdout, stderr=subprocess.PIPE,
                                            bufsize=0, preexec_fn=limit_file if limited else None)
            self.ready = threading.Event()
            self.log_failed = threading.Event()
            self.output, self.errors, self.threads = [], [], []
            processes.append(self)
            if closed:
                self.process.stdout.close()
                self.process.stdout = None
            def collect(stream, target, diagnostic):
                for line in iter(stream.readline, b""):
                    target.append(line)
                    if diagnostic and b"inline_ready " in line:
                        self.ready.set()
                    if diagnostic and b"log_error:" in line:
                        self.log_failed.set()
                stream.close()
            for stream, target, diagnostic in ((self.process.stdout, self.output, False),
                                                (self.process.stderr, self.errors, True)):
                if stream is not None:
                    thread = threading.Thread(target=collect, args=(stream, target, diagnostic), daemon=True)
                    thread.start()
                    self.threads.append(thread)

        def wait_ready(self):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if self.ready.wait(0.05):
                    return
                if self.process.poll() is not None:
                    break
            self.finish()
            raise AssertionError(("inline_ready missing", b"".join(self.errors)))

        def finish(self):
            try:
                code = self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise AssertionError("inline watchdog expired")
            for thread in self.threads:
                thread.join(timeout=2)
                assert not thread.is_alive(), "output collector did not finish"
            return code, b"".join(self.output), b"".join(self.errors)

    def exchange(value, delivered):
        client.sendto(value, ("127.0.0.1", port))
        try:
            packet, _ = server.recvfrom(4096)
        except socket.timeout:
            assert not delivered, ("expected ACCEPT but nothing arrived", value)
        else:
            assert delivered and packet == value, ("unexpected delivery", value, packet)

    def four_packets():
        for value, allowed in ((b"NORMAL", True), (b"SAFE BLOCKME", True),
                                (b"NOTICE", True), (b"BLOCKME", False)):
            exchange(value, allowed)

    def parse(output):
        return [json.loads(line) for line in output.splitlines()]

    def stats_of(output, count, accepted, dropped):
        rows = parse(output)
        assert all(row["mode"] == "inline" for row in rows)
        verdicts = [row for row in rows if row["event_type"] == "verdict"]
        assert len(verdicts) == count
        assert len({row["queue_packet_id"] for row in verdicts}) == count
        assert all(row["enforced"] and row["verdict_sent"] for row in verdicts)
        assert all(not row["enforced"] for row in rows if row["event_type"] != "verdict")
        assert all(row["timestamp_status"] == "receive" for row in verdicts)
        stats = rows[-1]
        assert stats["event_type"] == "stats" and stats["run_complete"] and not stats["capture_complete"]
        queue = stats["queue_stats"]
        assert queue["valid_ids"] == queue["attempts"] == accepted + dropped == count
        assert queue["accepted"] == accepted and queue["dropped"] == dropped
        assert queue["failed"] == queue["missing_ids"] == queue["close_errors"] == 0
        assert stats["actual_drop_packets"] == dropped and stats["actual_accept_packets"] == accepted
        assert stats["simulated_drop_packets"] == 0
        return rows, stats

    try:
        exchange(b"BEFORE_QUEUE", True)
        subprocess.run([nft, "-f", "-"], input=(
            f"add chain ip {table} input {{ type filter hook input priority 0; policy accept; }}\n"
            f"add rule ip {table} input ip protocol udp udp dport {port} queue num {queue_num}\n").encode(), check=True)
        exchange(b"NO_LISTENER", False)
        cases.append("no_listener_fails_closed")

        process = Process(["--packet-count", "4", "--log", "-"])
        process.wait_ready()
        four_packets()
        code, output, errors = process.finish()
        assert code == 0, errors
        rows, stats = stats_of(output, 4, 3, 1)
        assert stats["logical_rule_drop_packets"] == 1 and stats["detections"] == 2
        assert b"log_complete=1" in errors
        if len(sys.argv) > 4:
            with pathlib.Path(sys.argv[4]).open("xb") as trace:
                trace.write(output)
        cases.append("real_accept_pass_alert_drop_and_accounting")
        exchange(b"AFTER_STOP", False)
        cases.append("stopped_listener_fails_closed")

        for number, reason in ((signal.SIGINT, "sigint"), (signal.SIGTERM, "sigterm")):
            process = Process(["--log", "-"], flag_first=number == signal.SIGINT)
            process.wait_ready()
            process.process.send_signal(number)
            code, output, errors = process.finish()
            assert code == 0, errors
            _, stats = stats_of(output, 0, 0, 0)
            assert stats["stop_reason"] == reason and stats["timestamp"] is None
            cases.append("idle_" + reason + ("_flag_first" if number == signal.SIGINT else ""))

        original = Process(["--log", "-"])
        original.wait_ready()
        duplicate = subprocess.run(base + ["--log", "-"], capture_output=True, timeout=10, check=False)
        assert duplicate.returncode == 1 and b"Cannot bind NFQUEUE" in duplicate.stderr
        exchange(b"NORMAL", True)
        original.process.send_signal(signal.SIGTERM)
        code, output, errors = original.finish()
        assert code == 0, errors
        stats_of(output, 1, 1, 0)
        cases.append("duplicate_binding_preserves_original")

        icmp_table = table + "_icmp"
        subprocess.run([nft, "add", "table", "ip", icmp_table], check=True)
        try:
            subprocess.run([nft, "-f", "-"], input=(
                f"add chain ip {icmp_table} input {{ type filter hook input priority 1; policy accept; }}\n"
                f"add rule ip {icmp_table} input ip protocol icmp queue num {queue_num}\n").encode(), check=True)
            process = Process(["--packet-count", "2", "--log", "-"])
            process.wait_ready()
            request = bytearray(b"\x08\x00\x00\x00" + struct.pack("!HH", 0x4A37, 1) + b"A7PING")
            checksum = sum(struct.unpack("!" + "H" * (len(request) // 2), request))
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            request[2:4] = struct.pack("!H", (~checksum) & 65535)
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as ping:
                ping.settimeout(3)
                ping.sendto(request, ("127.0.0.1", 0))
                deadline = time.monotonic() + 3
                reply_seen = False
                while time.monotonic() < deadline:
                    packet, _ = ping.recvfrom(4096)
                    ip_header = (packet[0] & 15) * 4
                    if packet[ip_header] == 0 and packet.endswith(b"A7PING"):
                        reply_seen = True
                        break
                assert reply_seen, "unsupported ICMP should still receive ACCEPT"
            code, output, errors = process.finish()
            assert code == 0, errors
            rows, stats = stats_of(output, 2, 2, 0)
            assert stats["packets_skipped"] == 2
            assert all(row["inspection_status"] == "unsupported" for row in rows if row["event_type"] == "verdict")
            cases.append("unsupported_icmp_accepted_and_logged")
        finally:
            subprocess.run([nft, "delete", "table", "ip", icmp_table], check=False)

        with tempfile.TemporaryDirectory(prefix="miniips-a7-") as directory:
            for destination in ("closed", "limited_stdout", "limited_file"):
                path = pathlib.Path(directory) / (destination + ".jsonl")
                target = str(path) if destination == "limited_file" else "-"
                regular = path.open("wb") if destination == "limited_stdout" else None
                try:
                    process = Process(["--packet-count", "11", "--log", target],
                                      stdout=regular if regular else subprocess.PIPE,
                                      closed=destination == "closed", limited=destination != "closed")
                    process.wait_ready()
                    for _ in range(8):
                        exchange(b"NORMAL", True)
                    assert process.log_failed.wait(3), "expected logger failure before later traffic"
                    exchange(b"BLOCKME", False)
                    exchange(b"SAFE BLOCKME", True)
                    exchange(b"NOTICE", True)
                    code, output, errors = process.finish()
                    assert code == 1, errors
                    combined = output + errors
                    assert b"valid_ids=11 attempts=11 accepted=10 dropped=1 failed=0" in combined, combined
                    assert b"log_complete=0" in errors and errors.count(b"log_error:") == 1
                    cases.append("logger_" + destination + "_preserves_later_verdicts")
                finally:
                    if regular:
                        regular.close()
            log = pathlib.Path(directory) / "healthy.jsonl"
            process = Process(["--packet-count", "4", "--log", str(log)])
            process.wait_ready()
            four_packets()
            code, _, errors = process.finish()
            assert code == 0, errors
            stats_of(log.read_bytes(), 4, 3, 1)
            assert log.stat().st_mode & 0o777 == 0o600
            before = log.read_bytes()
            existing = subprocess.run(base + ["--log", str(log)], capture_output=True, timeout=10, check=False)
            assert existing.returncode == 1 and log.read_bytes() == before
            cases.append("file_0600_and_existing_preserved")

            failure_log = pathlib.Path(directory) / "human-failure.jsonl"
            with open("/dev/full", "wb", buffering=0) as full:
                process = Process(["--log", str(failure_log)], stdout=full)
                process.wait_ready()
                delivered = 0
                for _ in range(30):
                    if process.process.poll() is not None:
                        break
                    client.sendto(b"NORMAL", ("127.0.0.1", port))
                    try:
                        value, _ = server.recvfrom(4096)
                    except socket.timeout:
                        break
                    assert value == b"NORMAL"
                    delivered += 1
                code, _, errors = process.finish()
            assert code == 1 and delivered > 0, errors
            rows = parse(failure_log.read_bytes())
            counter = rows[-1]["queue_stats"]
            assert not rows[-1]["run_complete"]
            assert counter["callbacks"] == counter["valid_ids"] == counter["attempts"] == counter["accepted"] + counter["dropped"], {
                "counter": counter, "delivered": delivered, "stderr": errors.decode(errors="replace")}
            assert counter["accepted"] == delivered and counter["failed"] == 0
            assert rows[-1]["fallback_drop_packets"] == counter["dropped"]
            receipts = [row for row in rows if row["event_type"] == "verdict"]
            assert sum(row["action"] == "allow" for row in receipts) == delivered
            assert len({row["queue_packet_id"] for row in receipts}) == len(receipts)
            assert all(row["enforced"] for row in receipts)
            cases.append("human_exception_after_verdict_no_duplicate")

        permission = subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"] + base + ["--log", "-"],
                                    capture_output=True, timeout=10, check=False)
        assert permission.returncode == 1
        assert parse(permission.stdout)[-1]["mode"] == "inline"
        cases.append("permission_denied")
        subprocess.run([nft, "delete", "table", "ip", table], check=True)
        exchange(b"AFTER_CLEANUP", True)
        cases.append("own_rules_removed_communication_restored")
        print(json.dumps({"cases": len(cases), "failed": 0, "names": cases, "isolated": True,
                          "canonical_received": 4, "accepted": 3, "actual_drop_packets": 1,
                          "host_firewall_changed": False}))
    finally:
        for process in processes:
            if process.process.poll() is None:
                process.process.kill()
                process.process.wait(timeout=5)
        server.close()
        client.close()
        subprocess.run([nft, "delete", "table", "ip", table], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main()
