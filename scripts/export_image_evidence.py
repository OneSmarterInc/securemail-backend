"""Export the exact scanned images and SPDX SBOMs for subsequent CI attestation."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

TRIVY = (
    "aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / ".runtime/image-evidence"
    output.mkdir(parents=True, exist_ok=False)
    images = []
    for label in ["backend", "pq"]:
        tag = f"securemail-{label}:scan"
        image_id = subprocess.check_output(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag], text=True
        ).strip()
        archive = output / f"{label}.image.tar"
        subprocess.run(["docker", "save", "--output", str(archive), image_id], check=True)
        sbom = output / f"{label}.spdx.json"
        with sbom.open("wb") as stream:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    "/var/run/docker.sock:/var/run/docker.sock",
                    TRIVY,
                    "image",
                    "--image-src",
                    "docker",
                    "--format",
                    "spdx-json",
                    image_id,
                ],
                stdout=stream,
                check=True,
            )
        inventory = json.loads(sbom.read_text(encoding="utf-8"))
        if (
            not inventory.get("spdxVersion", "").startswith("SPDX-")
            or not inventory.get("packages")
            or sbom.stat().st_size > 16 * 1024 * 1024
        ):
            raise ValueError(f"Invalid, empty or oversized SBOM for {label}")
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        images.append(
            {
                "name": label,
                "docker_config_digest": image_id,
                "archive": archive.name,
                "archive_sha256": digest,
                "sbom": sbom.name,
                "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
            }
        )
    for name in ["requirements.lock", "requirements-test.lock"]:
        shutil.copyfile(root / name, output / name)
    (output / "manifest.json").write_text(
        json.dumps({"commit": os.environ["GITHUB_SHA"], "images": images}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
