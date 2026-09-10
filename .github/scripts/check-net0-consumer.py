#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Build a packaged NET0 backend as a dependency, never as its own example.

This is a maintainer test harness, not a consumer build dependency. The
materialized app runs plain Cargo offline with the usual runtime link script;
it has no build.rs or explicit cleanup --wrap arguments.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SYMBOLS = ("hmac_user_del_etc", "hmac_res_free_mac_user_etc")
sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_checker(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ".github/scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def toml(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {toml(v)}" for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(map(toml, value)) + "]"
    return json.dumps(value)


def materialize(backend, app):
    manifest = tomllib.loads((backend / "Cargo.toml").read_text(encoding="utf-8"))
    (app / "src/support").mkdir(parents=True)
    (app / ".cargo").mkdir()
    shutil.copyfile(backend / "examples/incremental_scan_profile.rs", app / "src/main.rs")
    for name in ("net0_storage.rs", "net0_initial_network.rs"):
        shutil.copyfile(backend / "examples/support" / name, app / "src/support" / name)
    for name in ("Cargo.lock", "rust-toolchain.toml"):
        shutil.copyfile(backend / name, app / name)
    dependencies = {"hisi-rf-ws63": {"path": "../" + backend.name, "default-features": False}}
    for name in ("hisi-rf-core", "hisi-hal", "critical-section", "embassy-time",
                 "embassy-net-driver", "static_cell", "smoltcp"):
        value = manifest["dependencies"][name]
        if isinstance(value, dict):
            value = {k: v for k, v in value.items() if k != "optional"}
        dependencies[name] = value
    dependencies.update(manifest["target"]['cfg(target_arch = "riscv32")']["dev-dependencies"])
    defaults = ["wpa2-personal", "standard-l2-initial-session-experiment",
                "incremental-connect-profile", "bootstrap-stage-diag", "firmware-example"]
    text = '[package]\nname = "net0-consumer"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n[dependencies]\n'
    text += "".join(f"{name} = {toml(value)}\n" for name, value in dependencies.items())
    text += "[features]\ndefault = " + toml(defaults) + "\n"
    for name in manifest["features"]:
        if name == "default":
            continue
        forwarding = ["hisi-rf-ws63/" + name]
        if name == "standard-l2-initial-session-experiment":
            forwarding.append("standard-l2")
        text += f"{name} = {toml(forwarding)}\n"
    text += "[profile.release]\n" + "".join(
        f"{key} = {toml(value)}\n" for key, value in manifest["profile"]["release"].items())
    (app / "Cargo.toml").write_text(text, encoding="utf-8")
    (app / ".cargo/config.toml").write_text('''[build]
target = "riscv32imfc-unknown-none-elf"
[unstable]
build-std = ["core", "alloc"]
[target.riscv32imfc-unknown-none-elf]
rustflags = ["-C", "link-arg=-Thisi-riscv-link.x", "-C", "link-arg=--no-relax"]
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if k not in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
        "WS63_WIFI_SSID", "WS63_WIFI_PASSPHRASE")}
    env["CARGO_NET_OFFLINE"] = "true"

    def run(command, cwd, expected_failure=False, missing_symbols=SYMBOLS):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        if expected_failure:
            if result.returncode == 0 or not all(
                    f"undefined symbol: __real_{name}" in result.stderr for name in missing_symbols):
                raise RuntimeError("missing-metadata fixture did not fail at the required native aliases\n" + result.stderr)
        elif result.returncode:
            raise RuntimeError("Cargo consumer gate failed\n" + result.stdout + result.stderr)
        return result

    with tempfile.TemporaryDirectory(prefix="net0 consumer \u6d4b\u8bd5 ") as temporary:
        workspace = Path(temporary)
        # Package in an independent copy: a parent workspace's patches/profile
        # must not participate in the dependency resolution under test.
        source = workspace / "source"
        source.mkdir()
        paths = subprocess.check_output(
            ["git", "ls-files", "--cached", "-z"], cwd=ROOT).decode("utf-8").split("\0")
        source_files = []
        for name in sorted(set(paths) - {""}):
            path = ROOT / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("source fixture must contain regular files only")
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            source_files.append({"path": name, "sha256": sha(path)})
        run(["cargo", "package", "--locked", "--offline", "--no-verify"], source)
        version = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
        package = source / "target/package" / f"hisi-rf-ws63-{version}.crate"
        with tarfile.open(package) as archive:
            archive.extractall(workspace, filter="data")
        backend = workspace / f"hisi-rf-ws63-{version}"
        app = workspace / "app"
        materialize(backend, app)
        # Resolve only the actual target build, not metadata for every host.
        # The new app needs its root entry added to the copied lock; all existing
        # package identities/checksums must remain from the packaged lock.
        def locked_packages(path):
            return {(item["name"], item["version"], item.get("source"), item.get("checksum"))
                    for item in tomllib.loads(path.read_text(encoding="utf-8"))["package"]}
        pinned = locked_packages(backend / "Cargo.lock")
        run(["cargo", "build", "--release", "--offline"], app)
        added = locked_packages(app / "Cargo.lock") - pinned
        if added != {("net0-consumer", "0.0.0", None, None)}:
            raise ValueError("external consumer changed pinned package identities")
        build = ["cargo", "build", "--release", "--locked", "--offline"]
        run(build, app)
        elf = app / "target/riscv32imfc-unknown-none-elf/release/net0-consumer"
        cleanup = load_checker("check-net0-cleanup")
        storage = load_checker("check-net0-storage")
        host_tx = load_checker("check-net0-host-tx")
        tx_report = host_tx.inspect(elf)
        tx_report["rejected_call_mutations"] = host_tx.tamper(elf)
        (output / "host-tx.json").write_text(json.dumps(tx_report, indent=2) + "\n")
        report = cleanup.inspect(elf)
        report["rejected_call_mutations"] = cleanup.tamper(elf)
        (output / "cleanup.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "storage.json").write_text(json.dumps(storage.inspect(elf), indent=2) + "\n")
        original_elf = sha(elf)
        run(build, app)
        if sha(elf) != original_elf:
            raise ValueError("unchanged incremental build changed the ELF")

        hook = backend / "src/netif_l2/user_cleanup.rs"
        original = hook.read_bytes()
        # Git checkouts may use CRLF on Windows. Mutate logical source lines,
        # then restore the exact original bytes, including their line endings.
        altered = original.decode("utf-8").replace("\r\n", "\n")
        for name in SYMBOLS:
            attribute = f'    #[link(kind = "link-arg", name = "--wrap={name}")]\n'
            if altered.count(attribute) != 1:
                raise ValueError("expected exactly one native-link attribute")
            altered = altered.replace(attribute, "")
        try:
            hook.write_text(altered, encoding="utf-8", newline="\n")
            run(build, app, expected_failure=True)
        finally:
            hook.write_bytes(original)
        run(build, app)
        if cleanup.inspect(elf)["edges"] != report["edges"]:
            raise ValueError("restored metadata changed the resolved graph")
        run(build + ["--features", "standard-l2-rx-stop-experiment"], app)
        rx_stop = load_checker("check-net0-rx-stop")
        rx_report = rx_stop.inspect(elf)
        rx_report["rejected_call_and_address_mutations"] = rx_stop.tamper(elf)
        (output / "rx-stop.json").write_text(json.dumps(rx_report, indent=2) + "\n")
        rx_mode = load_checker("check-net0-rx-mode")
        mode_report = rx_mode.inspect(elf)
        mode_report["rejected_mutations"] = rx_mode.tamper(elf)
        (output / "rx-mode.json").write_text(json.dumps(mode_report, indent=2) + "\n")
        hook = backend / "src/netif_l2/rx_mode.rs"
        original = hook.read_bytes()
        attribute = '    #[link(kind = "link-arg", name = "--wrap=frw_host_post_msg")]\n'
        altered = original.decode("utf-8").replace("\r\n", "\n")
        if altered.count(attribute) != 1:
            raise ValueError("expected exactly one RX-mode native-link attribute")
        try:
            hook.write_text(altered.replace(attribute, ""), encoding="utf-8", newline="\n")
            run(build + ["--features", "standard-l2-rx-stop-experiment"], app,
                expected_failure=True, missing_symbols=("frw_host_post_msg",))
        finally:
            hook.write_bytes(original)
        run(build + ["--features", "standard-l2-rx-stop-experiment"], app)
        if rx_mode.inspect(elf)["edges"] != mode_report["edges"]:
            raise ValueError("restored RX-mode metadata changed the producer call routing")
        origin_build = build + ["--features", "standard-l2-rx-origin-experiment"]
        run(origin_build, app)
        origin = load_checker("check-net0-rx-origin")
        origin_report = origin.inspect(elf)
        origin_report["rejected_mutations"] = origin.tamper(elf)
        (output / "rx-origin.json").write_text(json.dumps(origin_report, indent=2) + "\n")
        hook = backend / "src/netif_l2/rx_origin.rs"
        original = hook.read_bytes()
        attribute = '    #[link(kind = "link-arg", name = "--wrap=hh503_rx_set_ctrl_dscr")]\n'
        altered = original.decode("utf-8").replace("\r\n", "\n")
        if altered.count(attribute) != 1:
            raise ValueError("expected exactly one descriptor native-link attribute")
        try:
            hook.write_text(altered.replace(attribute, ""), encoding="utf-8", newline="\n")
            run(origin_build, app, expected_failure=True, missing_symbols=("hh503_rx_set_ctrl_dscr",))
        finally:
            hook.write_bytes(original)
        run(origin_build, app)
        if origin.inspect(elf)["edges"] != origin_report["edges"]:
            raise ValueError("restored descriptor metadata changed native call routing")
        result = {"schema": "net0-transitive-consumer/v1", "status": "pass",
                  "harness_sha256": sha(Path(__file__)),
                  "package_sha256": sha(package), "package_bytes": package.stat().st_size,
                  "source_files": source_files, "consumer_lock_sha256": sha(app / "Cargo.lock"),
                  "pinned_dependencies_unchanged": True,
                  "clean_offline": True, "incremental_unchanged": True,
                  "missing_metadata_rejected": list(SYMBOLS), "restored_build": True,
                  "space_unicode_path": True, "consumer_build_script": False,
                  "consumer_wrap_flags": False,
                  "rx_stop_experiment_link_verified": True,
                  "direct_rx_link_verified": True,
                  "missing_rx_mode_metadata_rejected": True,
                  "rx_origin_link_verified": True,
                  "missing_rx_origin_metadata_rejected": True,
                  "boundary": "Packaged path dependency and final-call/resource checks, not crates.io-only facade or HIL acceptance"}
        (output / "consumer.json").write_text(json.dumps(result, indent=2) + "\n")
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(app / name, output / ("consumer." + name))
        print(json.dumps({k: result[k] for k in ("schema", "status", "package_bytes", "boundary")}))


if __name__ == "__main__":
    main()
