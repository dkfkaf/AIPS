"""A8 TCP endpoint and bounded receive-pressure checks, private netns only.

Arguments: binary rules nft. Uses the A7 safety-token contract and guard regression.
"""
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    if sys.flags.optimize:
        raise RuntimeError("Inline verification forbids optimized Python")
    host = os.environ.get("MINIIPS_A7_HOST_NETNS")
    if not host or host == os.readlink("/proc/self/ns/net"):
        raise RuntimeError("Inline test requires a fresh netns; host changes forbidden")
    binary, rules, nft = (str(pathlib.Path(value).resolve()) for value in sys.argv[1:4])
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    table, queue_num, tcp_port, udp_port = "miniips_a8", 42421, 58428, 58429
    processes, results = [], []

    with tempfile.TemporaryDirectory(prefix="miniips-a8-") as directory:
        root = pathlib.Path(directory)

        class Process:
            def __init__(self, name):
                self.output_path, self.error_path = root / (name + ".jsonl"), root / (name + ".err")
                self.output = self.output_path.open("xb")
                self.errors = self.error_path.open("xb")
                self.process = subprocess.Popen(
                    [binary, "--mode", "inline", "--queue-num", str(queue_num), "--enable-inline",
                     "--rules", rules, "--log", "-"], stdout=self.output, stderr=self.errors)
                processes.append(self)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if b"inline_ready " in self.error_path.read_bytes():
                        return
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.02)
                raise AssertionError(("inline_ready missing", self.error_path.read_bytes()))

            def finish(self, stop=True):
                if stop and self.process.poll() is None:
                    self.process.send_signal(signal.SIGINT)
                code = self.process.wait(timeout=12)
                self.output.close()
                self.errors.close()
                rows = [json.loads(line) for line in self.output_path.read_bytes().splitlines()]
                assert rows and rows[-1]["event_type"] == "stats", self.error_path.read_bytes()
                stats = rows[-1]
                counters = stats["queue_stats"]
                assert counters["valid_ids"] == counters["attempts"]
                assert counters["attempts"] == counters["accepted"] + counters["dropped"] + counters["failed"]
                receipts = [row for row in rows if row["event_type"] == "verdict"]
                assert len({row["queue_packet_id"] for row in receipts}) == len(receipts)
                assert len(receipts) <= counters["attempts"]  # closing callbacks may lack receipts
                assert all(row["verdict_attempted"] and row["verdict_sent"] == row["enforced"] for row in receipts)
                assert stats["actual_drop_packets"] == counters["dropped"]
                assert stats["actual_accept_packets"] == counters["accepted"]
                assert stats["simulated_drop_packets"] == 0
                if any(counters[key] for key in ("failed", "missing_ids", "receive_errors", "close_errors")):
                    assert code == 1 and not stats["run_complete"]
                return code, rows, stats

        def receive(connection, expected):
            data = b""
            while len(data) < len(expected):
                part = connection.recv(len(expected) - len(data))
                assert part, ("unexpected TCP EOF", data, expected)
                data += part
            assert data == expected

        def assert_blocked(connection):
            try:
                data = connection.recv(4096)
            except socket.timeout:
                return
            raise AssertionError(("blocked TCP bytes arrived or connection closed", data))

        subprocess.run([nft, "add", "table", "ip", table], check=True)
        try:
            subprocess.run([nft, "-f", "-"], input=(
                f"add chain ip {table} input {{ type filter hook input priority 0; policy accept; }}\n"
                f"add rule ip {table} input tcp dport {tcp_port} queue num {queue_num}\n"
                f"add rule ip {table} input tcp sport {tcp_port} queue num {queue_num}\n"
                f"add rule ip {table} input udp dport {udp_port} queue num {queue_num}\n"
            ).encode(), check=True)

            for name in ("tcp_normal_pass_alert", "tcp_packet_drop", "tcp_split_stream_drop"):
                process = Process(name)
                with socket.socket() as server:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind(("127.0.0.1", tcp_port))
                    server.listen(1)
                    server.settimeout(3)
                    with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
                        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(0.6)
                            if name == "tcp_normal_pass_alert":
                                for value in (b"NORMAL", b"SAFE BLOCKME", b"NOTICE"):
                                    client.sendall(value)
                                    receive(connection, value)
                            elif name == "tcp_packet_drop":
                                client.sendall(b"BLOCKME")
                                assert_blocked(connection)
                            else:
                                client.sendall(b"HEL")
                                receive(connection, b"HEL")
                                client.sendall(b"LO")
                                assert_blocked(connection)
                time.sleep(0.15)  # let FIN/ACKs drain while the listener is alive
                code, rows, stats = process.finish()
                assert code == 0 and stats["run_complete"], (code, stats)
                verdicts = [row for row in rows if row["event_type"] == "verdict"]
                if name == "tcp_normal_pass_alert":
                    assert any(row["sid"] == 8000 and row["action"] == "allow" for row in verdicts)
                    assert any(row["event_type"] == "alert" and row["sid"] == 8002 for row in rows)
                    assert stats["logical_rule_drop_packets"] == 0
                else:
                    sid = 8001 if name == "tcp_packet_drop" else 8003
                    assert any(row["sid"] == sid and row["action"] == "drop" and row["enforced"] for row in verdicts)
                    assert stats["logical_rule_drop_packets"] > 0 and stats["actual_drop_packets"] > 0
                results.append({"name": name, "queue_stats": stats["queue_stats"],
                                "earlier_prefix_delivered": name == "tcp_split_stream_drop"})

            # Remove only our own TCP rules so delayed TCP retransmissions cannot
            # contaminate the UDP pressure counters in the next binding.
            subprocess.run([nft, "flush", "chain", "ip", table, "input"], check=True)
            subprocess.run([nft, "add", "rule", "ip", table, "input", "udp", "dport",
                            str(udp_port), "queue", "num", str(queue_num)], check=True)
            process = Process("receive_pressure")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                server.bind(("127.0.0.1", udp_port))
                process.process.send_signal(signal.SIGSTOP)
                _, status = os.waitpid(process.process.pid, os.WUNTRACED)
                assert os.WIFSTOPPED(status)
                sent = 16384
                for _ in range(sent):
                    client.sendto(b"NORMAL" + b"X" * 256, ("127.0.0.1", udp_port))
                raw = pathlib.Path("/proc/net/netfilter/nfnetlink_queue").read_text()
                assert any(line.split()[0] == str(queue_num) for line in raw.splitlines())
                process.process.send_signal(signal.SIGCONT)
                code, _, stats = process.finish(stop=False)
                assert code == 1 and not stats["run_complete"], stats
                assert stats["queue_stats"]["receive_errors"] > 0
                assert stats["queue_stats"]["overflow_errors"] > 0
                assert stats["queue_stats"]["valid_ids"] < sent
                results.append({"name": "bounded_receive_pressure_error_and_cleanup", "sent": sent,
                                "exit_code": code, "queue_stats": stats["queue_stats"],
                                "kernel_queue_snapshot_raw": raw})
            print(json.dumps({"cases": len(results), "failed": 0, "isolated": True,
                              "host_firewall_changed": False, "results": results}))
        finally:
            for process in processes:
                if process.process.poll() is None:
                    process.process.kill()  # SIGKILL also terminates a SIGSTOP'ed child
                    process.process.wait(timeout=5)
                process.output.close()
                process.errors.close()
            subprocess.run([nft, "delete", "table", "ip", table], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    main()
