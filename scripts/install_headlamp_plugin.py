#!/usr/bin/env python3
"""Install the dreamstack-net build of the Kubescape Headlamp plugin into Headlamp desktop.

Runs on Windows, Linux and macOS with only the Python standard library (3.8 or newer).
On Windows, run it with `py` instead of `python3`.

  python3 install_headlamp_plugin.py                       latest release of the fork
  python3 install_headlamp_plugin.py --tag v0.11.2-ds.1    a specific release
  python3 install_headlamp_plugin.py --build               build main from source (needs Node.js and Go)
  python3 install_headlamp_plugin.py --build --ref BRANCH  build another branch, tag or commit
  python3 install_headlamp_plugin.py --source PATH         build a local checkout (needs Node.js and Go)
  python3 install_headlamp_plugin.py --uninstall

The plugin is installed as user-plugins/headlamp_kubescape, the folder the Plugin Catalog uses
for Kubescape, so it replaces a catalog install. Two reasons: Headlamp only loads the plugins/
folder in Plugin Development Mode, and the plugin finds its data files through the first plugin
folder with "kubescape" in its name, so only one copy may be installed. Anything it replaces is
moved to plugin-backups/. Restart Headlamp afterwards. Installing Kubescape from the Plugin
Catalog again overwrites this build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = "dreamstack-net/headlamp-plugin-v2"
GITHUB = "https://github.com"
ASSET = "kubescape-plugin.tar.gz"
PACKAGE_NAME = "kubescape-plugin"
PLUGIN_FOLDER = "headlamp_kubescape"
KEEP_BACKUPS = 3

# Data files the plugin reads at runtime; the same ones the Makefile's `download` target fetches.
CEL_RELEASE = "https://github.com/kubescape/cel-admission-library/releases/latest/download"
CEL_TEST_RESOURCES = (
    "https://raw.githubusercontent.com/kubescape/cel-admission-library/refs/heads/main/test-resources"
)
REGO_RELEASE = "https://github.com/kubescape/regolibrary/releases/download/v2"
VAP_TEST_FILES = [
    "deployment.yaml",
    "deployment-for-list-items.yaml",
    "pod-capabilities.yaml",
    "service-account.yaml",
    "deployment-with-common-label-1.yaml",
    "pod-for-list-items.yaml",
    "service.yaml",
    "deployment-with-common-label-2.yaml",
    "pod.yaml",
]


class InstallError(Exception):
    pass


class NotFound(InstallError):
    pass


def log(message: str) -> None:
    print(message, flush=True)


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "headlamp-plugin-installer"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise NotFound(f"{url}: not found") from None
        raise InstallError(f"{url}: HTTP {error.code}") from None
    except urllib.error.URLError as error:
        raise InstallError(f"{url}: {error.reason}") from None


# --- Where Headlamp keeps its plugins ------------------------------------------------------


def headlamp_dir() -> Path:
    """Headlamp's data folder, resolved the way Headlamp does (env-paths: data if it exists, else config)."""
    home = Path.home()
    if sys.platform == "win32":
        data = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Headlamp" / "Data"
        config = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / "Headlamp" / "Config"
        candidates = [data, config]
    elif sys.platform == "darwin":
        candidates = [
            home / "Library" / "Application Support" / "Headlamp",
            home / "Library" / "Preferences" / "Headlamp",
        ]
    else:
        data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share") / "Headlamp"
        config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / "Headlamp"
        flatpak = home / ".var" / "app" / "io.kinvolk.Headlamp"
        candidates = [data, config, flatpak / "data" / "Headlamp", flatpak / "config" / "Headlamp"]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    # Headlamp has not run yet; it will use the config folder.
    return candidates[1]


# --- Getting the plugin files --------------------------------------------------------------


def find_plugin(root: Path) -> Path:
    for package_json in sorted(root.rglob("package.json")):
        if "node_modules" not in package_json.parts and (package_json.parent / "main.js").is_file():
            return package_json.parent
    raise InstallError(f"no folder with main.js and package.json in {root}")


def extract_tar(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest, filter="data")
        else:
            root = dest.resolve()
            for member in tar.getmembers():
                target = (dest / member.name).resolve()
                if not (member.isfile() or member.isdir()) or root not in (target, *target.parents):
                    raise InstallError(f"unsafe entry in {archive.name}: {member.name}")
            tar.extractall(dest)
    return find_plugin(dest)


def download_release(repo: str, tag: str, work: Path) -> Path:
    base = f"{GITHUB}/{repo}/releases/" + ("latest/download" if tag == "latest" else f"download/{tag}")
    log(f"Downloading {base}/{ASSET}")
    try:
        archive = fetch(f"{base}/{ASSET}")
        checksum = fetch(f"{base}/{ASSET}.sha256").decode().split()[0].lower()
    except NotFound:
        raise InstallError(
            f"release {tag!r} of {repo} has no {ASSET} (or no {ASSET}.sha256). "
            "Publish one with the 'Release plugin' workflow, or use --build."
        ) from None
    actual = hashlib.sha256(archive).hexdigest()
    if actual != checksum:
        raise InstallError(f"checksum mismatch for {ASSET}: expected {checksum}, got {actual}")
    path = work / ASSET
    path.write_bytes(archive)
    return extract_tar(path, work / "release")


def download_source(repo: str, ref: str, work: Path) -> Path:
    url = f"{GITHUB}/{repo}/archive/{ref}.zip"
    log(f"Downloading source {url}")
    try:
        data = fetch(url)
    except NotFound:
        raise InstallError(f"{repo} has no branch, tag or commit {ref!r}") from None
    archive = work / "source.zip"
    archive.write_bytes(data)
    dest = work / "source"
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)
    (top,) = [p for p in dest.iterdir() if p.is_dir()]
    return top


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise InstallError(
            f"'{name}' is not on PATH. Building needs Node.js 24 (with npm) and Go 1.26 or newer; "
            "or drop --build/--source to download a prebuilt release."
        )
    return path


def run(cmd: list[str], cwd: Path, env: dict | None = None, capture: bool = False) -> str:
    log("  $ " + " ".join([Path(cmd[0]).stem, *cmd[1:]]))
    result = subprocess.run(
        cmd, cwd=cwd, env=env, universal_newlines=True, stdout=subprocess.PIPE if capture else None
    )
    if result.returncode != 0:
        raise InstallError(f"'{' '.join(cmd)}' failed with exit code {result.returncode}")
    return result.stdout.strip() if capture else ""


def download_data_files(public: Path) -> None:
    log("Downloading Kubescape controls, frameworks and admission policies")
    public.mkdir(exist_ok=True)
    (public / "basic-control-configuration.yaml").write_bytes(
        fetch(f"{CEL_RELEASE}/basic-control-configuration.yaml")
    )
    (public / "validating-admission-policies.yaml").write_bytes(
        fetch(f"{CEL_RELEASE}/kubescape-validating-admission-policies.yaml")
    )
    (public / "vap-test-files.yaml").write_bytes(
        b"".join(b"\n---\n" + fetch(f"{CEL_TEST_RESOURCES}/{name}") for name in VAP_TEST_FILES)
    )
    (public / "vap-test-files-index.yaml").write_bytes("".join(f"{n}\n" for n in VAP_TEST_FILES).encode())
    frameworks = json.loads(fetch(f"{REGO_RELEASE}/frameworks"))
    for framework in frameworks:
        framework["controls"] = []
    (public / "frameworks.json").write_bytes(json.dumps(frameworks, indent=2).encode())
    (public / "controls.json").write_bytes(fetch(f"{REGO_RELEASE}/controls"))
    (public / "rego-rules.json").write_bytes(fetch(f"{REGO_RELEASE}/rules"))


def build(src: Path, work: Path) -> Path:
    """Same steps as the release workflow: npm ci, make download, headlamp-plugin build, make build."""
    node, npm, go = tool("node"), tool("npm"), tool("go")
    node_version = run([node, "--version"], src, capture=True)
    if int(node_version.lstrip("v").split(".")[0]) < 22:
        raise InstallError(f"Node.js {node_version} is too old; the plugin is built with Node.js 24")

    log(f"Building {src}")
    run([npm, "ci", "--no-audit", "--no-fund"], src)
    # wasm_exec.js has to come from the Go release that builds main.wasm.
    goroot = Path(run([go, "-C", "go", "env", "GOROOT"], src, capture=True))
    wasm_exec = next(
        (p for p in (goroot / "lib" / "wasm" / "wasm_exec.js", goroot / "misc" / "wasm" / "wasm_exec.js") if p.is_file()),
        None,
    )
    if wasm_exec is None:
        raise InstallError(f"wasm_exec.js not found in Go installation {goroot}")
    shutil.copyfile(wasm_exec, src / "src" / "wasm" / "wasm_exec.js")
    download_data_files(src / "public")
    run([npm, "run", "build"], src)
    env = dict(os.environ, GOOS="js", GOARCH="wasm")
    run([go, "-C", "go", "build", "-ldflags=-s -w", "-o", "../dist/main.wasm", "cmd/main.go"], src, env=env)

    out = work / "kubescape-plugin"
    shutil.copytree(src / "dist", out)
    shutil.copyfile(src / "package.json", out / "package.json")
    return out


# --- Installing -------------------------------------------------------------------------------


def package_info(folder: Path) -> dict:
    try:
        return json.loads((folder / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def other_kubescape_folders(base: Path, target: Path) -> list[Path]:
    found = []
    for parent in (base / "user-plugins", base / "plugins"):
        if not parent.is_dir():
            continue
        for folder in sorted(parent.iterdir()):
            if folder == target or not (folder / "main.js").is_file():
                continue
            if "kubescape" in folder.name.lower() or package_info(folder).get("name") == PACKAGE_NAME:
                found.append(folder)
    return found


def move_to_backup(folder: Path, backups: Path, name: str) -> Path:
    backups.mkdir(parents=True, exist_ok=True)
    dest, n = backups / name, 1
    while dest.exists():
        dest, n = backups / f"{name}.{n}", n + 1
    shutil.move(str(folder), str(dest))
    return dest


def prune_backups(backups: Path) -> None:
    pattern = re.compile(rf"^{PLUGIN_FOLDER}-\d{{8}}-\d{{6}}(\.\d+)?$")
    ours = sorted(p for p in backups.iterdir() if pattern.match(p.name)) if backups.is_dir() else []
    for old in ours[:-KEEP_BACKUPS]:
        shutil.rmtree(old, ignore_errors=True)


def install(plugin: Path, base: Path) -> Path:
    for required in ("main.js", "package.json", "main.wasm"):
        if not (plugin / required).is_file():
            raise InstallError(f"{required} is missing from the plugin build in {plugin}")

    user_plugins = base / "user-plugins"
    target = user_plugins / PLUGIN_FOLDER
    backups = base / "plugin-backups"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    user_plugins.mkdir(parents=True, exist_ok=True)

    # Stage next to user-plugins (same disk, so the final rename is atomic) but outside it,
    # so Headlamp never sees a half-copied plugin.
    staging = Path(tempfile.mkdtemp(prefix=".kubescape-install-", dir=base))
    previous = None
    try:
        shutil.copytree(plugin, staging / PLUGIN_FOLDER)
        for other in other_kubescape_folders(base, target):
            dest = move_to_backup(other, backups, f"{other.parent.name}-{other.name}-{stamp}")
            log(f"Moved {other} to {dest} (only one Kubescape plugin can be installed)")
        if target.exists():
            previous = move_to_backup(target, backups, f"{PLUGIN_FOLDER}-{stamp}")
        os.replace(staging / PLUGIN_FOLDER, target)
    except PermissionError as error:
        if previous is not None and not target.exists():
            shutil.move(str(previous), str(target))
        raise InstallError(f"{error}\nClose Headlamp and run the installer again.") from None
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    if previous is not None:
        log(f"Previous version saved to {previous}")
    prune_backups(backups)
    return target


def uninstall(base: Path) -> None:
    target = base / "user-plugins" / PLUGIN_FOLDER
    if not target.is_dir():
        log(f"Nothing to remove: {target} does not exist")
        return
    dest = move_to_backup(target, base / "plugin-backups", f"{PLUGIN_FOLDER}-{time.strftime('%Y%m%d-%H%M%S')}")
    log(f"Moved {target} to {dest}")
    log("Restart Headlamp. Install Kubescape from the Plugin Catalog to get the upstream version back.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=__doc__.split("\n\n", 1)[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--tag", default="latest", help="release to install (default: the latest release)")
    source.add_argument("--build", action="store_true", help="build from source on GitHub instead of downloading a release")
    source.add_argument("--source", type=Path, metavar="PATH", help="build from a local checkout")
    source.add_argument("--archive", type=Path, metavar="FILE", help="install a plugin .tar.gz you already have")
    source.add_argument("--uninstall", action="store_true", help="remove the plugin (moved to plugin-backups)")
    parser.add_argument("--ref", default="main", help="branch, tag or commit for --build (default: main)")
    parser.add_argument("--repo", default=REPO, help=f"GitHub repository (default: {REPO})")
    parser.add_argument("--headlamp-dir", type=Path, metavar="PATH", help="Headlamp data folder (default: detected)")
    args = parser.parse_args(argv)

    base = args.headlamp_dir or headlamp_dir()
    log(f"Headlamp folder: {base}")
    try:
        if args.uninstall:
            uninstall(base)
            return 0
        work = Path(tempfile.mkdtemp(prefix="headlamp-plugin-"))
        try:
            if args.archive:
                plugin = extract_tar(args.archive.resolve(), work / "archive")
            elif args.source:
                plugin = build(args.source.resolve(), work)
            elif args.build:
                plugin = build(download_source(args.repo, args.ref, work), work)
            else:
                plugin = download_release(args.repo, args.tag, work)
            target = install(plugin, base)
            version = package_info(target).get("version", "unknown version")
        finally:
            # node_modules can hold read-only files on Windows; a leftover temp folder is harmless.
            shutil.rmtree(work, ignore_errors=True)
    except InstallError as error:
        log(f"ERROR: {error}")
        return 1
    except KeyboardInterrupt:
        log("Interrupted")
        return 130

    log(f"Installed {PACKAGE_NAME} {version} in {target}")
    log("Restart Headlamp to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
