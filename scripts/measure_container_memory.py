"""Sample selected Docker containers during a manual upload/download workload.

Example: python scripts/measure_container_memory.py --seconds 180 api-id worker-id
Prints only resource statistics, never environment variables or logs.
"""

import argparse
import json
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("containers", nargs="+")
    parser.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", *args.containers],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in result.stdout.splitlines():
            sample = json.loads(line)
            print(
                json.dumps(
                    {
                        "sampled_at": time.time(),
                        "container": sample["Name"],
                        "memory": sample["MemUsage"],
                        "cpu": sample["CPUPerc"],
                    }
                ),
                flush=True,
            )
        time.sleep(1)
    for container in args.containers:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{json .State}}", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        state = json.loads(result.stdout)
        print(
            json.dumps(
                {
                    "container": container,
                    "running": state["Running"],
                    "oom_killed": state["OOMKilled"],
                    "exit_code": state["ExitCode"],
                }
            )
        )
        if state["OOMKilled"] or not state["Running"]:
            raise SystemExit("Capacity check failed: container stopped or was OOM-killed.")


if __name__ == "__main__":
    main()
