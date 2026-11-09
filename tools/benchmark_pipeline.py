"""Reproducible C++ CLI PCAP/JSONL baseline; no network or AI dependencies.

Requires GNU /usr/bin/time. Creates a NEW report, never overwrites one.
Wall/N is amortized pipeline cost including startup and logging, not packet latency.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import platform
import signal
import statistics
import struct
import subprocess
import tempfile
import time

CHILD_TIMEOUT_SECONDS = 120


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_pcap(path, count):
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    addresses = (bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2)))
    markers = (b"NORMAL", b"SAFE BLOCKME", b"NOTICE", b"BLOCKME")
    frame_bytes = 0
    with path.open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index in range(count):
            payload = markers[index % 4] + b"X" * 64
            source_port, destination_port = 10000 + index % 128, 58429
            source, destination = addresses
            if (index // 128) % 2:
                source, destination = destination, source
                source_port, destination_port = destination_port, source_port
            udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), index % 65536,
                             0x4000, 64, 17, 0, source, destination)
            checksum = sum(struct.unpack("!10H", ip))
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            ip = ip[:10] + struct.pack("!H", (~checksum) & 65535) + ip[12:]
            frame = ethernet + ip + udp
            output.write(struct.pack("<IIII", 1 + index // 10000, (index % 10000) * 100,
                                     len(frame), len(frame)))
            output.write(frame)
            frame_bytes += len(frame)
    return frame_bytes


def parse_summaries(text):
    return {line.split()[0]: dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)
            for line in text.splitlines() if "_summary " in line}


def run_once(binary, rules, pcap, root, count, case, ordinal):
    timing = root / f"{case}-{ordinal}.time"
    errors = root / f"{case}-{ordinal}.stderr"
    command = [str(binary), "--mode", "pcap", "--input", str(pcap), "--log", "-"]
    if case == "fixed_rules":
        command += ["--rules", str(rules)]
    with errors.open("xb") as diagnostics:
        start = time.perf_counter_ns()
        with subprocess.Popen(
            ["/usr/bin/time", "-f", "%U %S %M", "-o", str(timing), "--"] + command,
            stdout=subprocess.DEVNULL, stderr=diagnostics, start_new_session=True) as child:
            try:
                code = child.wait(timeout=CHILD_TIMEOUT_SECONDS)
            finally:
                if child.poll() is None:
                    # GNU time owns a child; killing only time would orphan miniips.
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
        elapsed_ns = time.perf_counter_ns() - start
    diagnostic_text = errors.read_text()
    require(code == 0, f"Benchmark child failed: {diagnostic_text}")
    summaries = parse_summaries(diagnostic_text)
    packet = summaries.get("pcap_summary", {})
    require(packet == {"packets": str(count), "parsed": str(count), "skipped": "0"},
            f"Unexpected packet counts: {packet}")
    flow = summaries.get("flow_summary", {})
    require(flow.get("created") == str(min(count, 128)) and flow.get("rejected") == "0",
            f"Unexpected Flow counts: {flow}")
    logger = summaries.get("logger_summary", {})
    require(logger.get("log_complete") == "1" and logger.get("failed") == "0"
            and logger.get("dropped") == "0" and logger.get("io_errors") == "0"
            and logger.get("attempted") == logger.get("written"), f"Logger incomplete: {logger}")
    if case == "fixed_rules":
        detection = summaries.get("detection_summary", {})
        require(detection.get("packets") == str(count) and detection.get("events") == str(count * 3 // 4)
                and detection.get("simulated_drops") == str(count // 4)
                and detection.get("enforced") == "false", f"Unexpected rule counters: {detection}")
    cpu_user, cpu_system, rss = timing.read_text().strip().split()
    seconds = elapsed_ns / 1e9
    return {"ordinal": ordinal, "wall_seconds": seconds, "packets_per_second": count / seconds,
            "amortized_wall_us_per_packet": elapsed_ns / count / 1000,
            "child_user_seconds": float(cpu_user), "child_system_seconds": float(cpu_system),
            "child_max_rss_kib": int(rss), "summaries": summaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("rules", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--packets", type=int, default=50000)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.packets < 4 or args.packets % 4 or args.repeats < 1:
        parser.error("packets must be >=4 and divisible by4; repeats must be positive")
    if args.output.exists():
        parser.error("report already exists; select a NEW output path")
    binary, rules = args.binary.resolve(strict=True), args.rules.resolve(strict=True)
    require(pathlib.Path("/usr/bin/time").is_file(), "GNU /usr/bin/time is required")
    with tempfile.TemporaryDirectory(prefix="miniips-benchmark-") as directory:
        root = pathlib.Path(directory)
        pcap = root / "input.pcap"
        frame_bytes = generate_pcap(pcap, args.packets)
        results = []
        for case in ("no_rules", "fixed_rules"):
            warmup = run_once(binary, rules, pcap, root, args.packets, case, "warmup")
            trials = [run_once(binary, rules, pcap, root, args.packets, case, index)
                      for index in range(args.repeats)]
            results.append({"case": case, "warmup_excluded": warmup, "trials": trials,
                            "median_pps": statistics.median(row["packets_per_second"] for row in trials),
                            "min_pps": min(row["packets_per_second"] for row in trials),
                            "max_pps": max(row["packets_per_second"] for row in trials),
                            "median_amortized_us_per_packet": statistics.median(
                                row["amortized_wall_us_per_packet"] for row in trials),
                            "peak_child_rss_kib": max(row["child_max_rss_kib"] for row in trials)})
        cpu = next((line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")), "unknown")
        report = {"stage": "A8", "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "path": "C++ CLI PCAP->Engine->JSONL stdout /dev/null, no AI",
                  "packets": args.packets, "bidirectional_flows": min(args.packets, 128),
                  "frame_bytes": frame_bytes, "pcap_bytes": pcap.stat().st_size,
                  "input_sha256": sha256(pcap), "binary_sha256": sha256(binary),
                  "rules_sha256": sha256(rules), "warmup_per_case": 1, "trials_per_case": args.repeats,
                  "environment": {"uname": list(platform.uname()), "cpu": cpu,
                                  "available_cpus": len(os.sched_getaffinity(0)),
                                  "mem_total": pathlib.Path("/proc/meminfo").read_text().splitlines()[0],
                                  "os_release": pathlib.Path("/etc/os-release").read_text(),
                                  "python": platform.python_version(),
                                  "gnu_time": subprocess.check_output(["/usr/bin/time", "--version"], text=True).splitlines()[0],
                                  "input_storage": "system temporary directory (page cache warmed)",
                                  "binary_path": str(binary)},
                  "limits": ["synthetic UDP and seven synthetic rules, no attack dataset or accuracy claim",
                             "startup, PCAP reads, Flow, rule matching and JSON serialization included",
                             "amortized wall/N is not individual packet latency or p99",
                             "not NFQUEUE/live/wire throughput; no CPU pinning or cache eviction",
                             "GNU time RSS is each child maximum, not Python/global cumulative RSS"],
                  "results": results}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, ensure_ascii=False)
        output.write("\n")
    print(json.dumps({"output": str(args.output), "results": [
        {key: row[key] for key in ("case", "median_pps", "median_amortized_us_per_packet", "peak_child_rss_kib")}
        for row in results]}))


if __name__ == "__main__":
    main()
