#!/usr/bin/env python3
"""Install the dreamstack-net build of the Kubescape Headlamp plugin into Headlamp desktop.

Runs on Windows, Linux and macOS with only the Python standard library (3.8 or newer).
On Windows, run it with `py` instead of `python3`.

  python3 install_headlamp_plugin.py                       latest release of the fork
  python3 install_headlamp_plugin.py --tag v0.11.2-ds.1    a specific release
  python3 install_headlamp_plugin.py --build               build main from source (needs Node.js and Go)
  python3 install_headlamp_plugin.py --build --ref BRANCH  build another branch, tag or commit
  python3 install_headlamp_plugin.py --source PATH         build a copy of a local checkout (needs Node.js and Go)
  python3 install_headlamp_plugin.py --source . --output DIR   build it into DIR instead of installing it
  python3 install_headlamp_plugin.py --uninstall

The plugin is installed as user-plugins/headlamp_kubescape, the folder the Plugin Catalog uses
for Kubescape, so it replaces a catalog install. Two reasons: Headlamp only loads the plugins/
folder in Plugin Development Mode, and the plugin finds its data files through the first plugin
folder with "kubescape" in its name, so only one copy may be installed. Anything it replaces is
moved to plugin-backups/. Restart Headlamp afterwards. Installing Kubescape from the Plugin
Catalog again overwrites this build.

With --output, the plugin is copied into a folder of its own instead, such as the plugins
directory of a Headlamp server (the end-to-end tests run one), and Headlamp desktop is left alone.
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

# Data files the plugin reads at runtime; the same ones the Makefile's `download` target fetches,
# in the versions scripts/data-sources.json of the source names.
DATA_SOURCES = Path("scripts") / "data-sources.json"
CEL_RELEASE = "https://github.com/kubescape/cel-admission-library/releases/download/{version}"
CEL_TEST_RESOURCES = "https://raw.githubusercontent.com/kubescape/cel-admission-library/{version}/test-resources"
REGO_RELEASE = "https://github.com/kubescape/regolibrary/releases/download/{version}"

# the folders of a checkout that a build does not need, or makes again, and what the end-to-end
# tests leave in e2e/ (the plugin build, the kubeconfig of their Headlamp, Playwright's results)
NOT_COPIED = shutil.ignore_patterns(
    ".git",
    "node_modules",
    "dist",
    "public",
    "__pycache__",
    ".plugins",
    ".headlamp",
    "test-results",
    "playwright-report",
)


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


def verify_attestation(archive: Path, repo: str) -> None:
    """Checks with the GitHub CLI that the release workflow of the repository built the archive."""
    gh = shutil.which("gh")
    if not gh:
        raise InstallError("--verify-attestation needs the GitHub CLI (gh) on PATH")
    log(f"Verifying that {repo} built {archive.name}")
    result = subprocess.run(
        [gh, "attestation", "verify", str(archive), "--repo", repo],
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise InstallError(f"the attestation of {archive.name} could not be verified:\n{result.stdout.strip()}")


def download_release(repo: str, tag: str, work: Path, attestation: bool = False) -> Path:
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
    # the checksum shows the archive is whole; the attestation, that the release workflow made it
    if attestation:
        verify_attestation(path, repo)
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
    folders = [p for p in dest.iterdir() if p.is_dir()]
    if len(folders) != 1:
        raise InstallError(f"the source archive of {ref!r} does not hold one folder")
    return folders[0]


def copy_checkout(src: Path, work: Path) -> Path:
    """A copy of a checkout to build in, so that the build does not change the checkout."""
    if not (src / "package.json").is_file():
        raise InstallError(f"{src} is not a checkout of the plugin: it has no package.json")
    log(f"Copying {src} to build it apart from the checkout")
    copy = work / "source"
    shutil.copytree(src, copy, ignore=NOT_COPIED)
    return copy


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


def data_sources(src: Path) -> dict:
    path = src / DATA_SOURCES
    try:
        sources = json.loads(path.read_text(encoding="utf-8"))
        return {
            "cel": sources["celAdmissionLibrary"],
            "rego": sources["regolibrary"],
            "vap_test_files": list(sources["vapTestFiles"]),
        }
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise InstallError(f"{path} does not name the versions of the Kubescape data: {error}") from None


def download_data_files(public: Path, sources: dict) -> None:
    log(
        f"Downloading Kubescape controls and frameworks {sources['rego']} "
        f"and admission policies {sources['cel']}"
    )
    cel = CEL_RELEASE.format(version=sources["cel"])
    cel_tests = CEL_TEST_RESOURCES.format(version=sources["cel"])
    rego = REGO_RELEASE.format(version=sources["rego"])
    test_files = sources["vap_test_files"]
    public.mkdir(exist_ok=True)
    (public / "basic-control-configuration.yaml").write_bytes(fetch(f"{cel}/basic-control-configuration.yaml"))
    (public / "validating-admission-policies.yaml").write_bytes(
        fetch(f"{cel}/kubescape-validating-admission-policies.yaml")
    )
    (public / "vap-test-files.yaml").write_bytes(
        b"".join(b"\n---\n" + fetch(f"{cel_tests}/{name}") for name in test_files)
    )
    (public / "vap-test-files-index.yaml").write_bytes("".join(f"{n}\n" for n in test_files).encode())
    frameworks = json.loads(fetch(f"{rego}/frameworks"))
    for framework in frameworks:
        framework["controls"] = []
    (public / "frameworks.json").write_bytes(json.dumps(frameworks, indent=2).encode())
    (public / "controls.json").write_bytes(fetch(f"{rego}/controls"))
    (public / "rego-rules.json").write_bytes(fetch(f"{rego}/rules"))


def build(src: Path, work: Path) -> Path:
    """Same steps as the release workflow: npm ci, make download, headlamp-plugin build, make build."""
    node, npm, go = tool("node"), tool("npm"), tool("go")
    sources = data_sources(src)
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
    download_data_files(src / "public", sources)
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


def check_build(plugin: Path) -> None:
    for required in ("main.js", "package.json", "main.wasm"):
        if not (plugin / required).is_file():
            raise InstallError(f"{required} is missing from the plugin build in {plugin}")


def write_output(plugin: Path, output: Path) -> Path:
    """Copies the plugin into the folder output instead of installing it into Headlamp desktop.

    A folder that holds something else than a build of the plugin is not replaced. The folder
    itself is kept and only its contents replaced, as a Headlamp container may have it mounted.
    """
    check_build(plugin)
    output = output.resolve()
    if output.exists():
        if not output.is_dir():
            raise InstallError(f"{output} is not a folder")
        if any(output.iterdir()) and package_info(output).get("name") != PACKAGE_NAME:
            raise InstallError(f"{output} holds something else than a build of {PACKAGE_NAME}; not replacing it")
        for child in output.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    shutil.copytree(plugin, output, dirs_exist_ok=True)
    return output


def install(plugin: Path, base: Path) -> Path:
    check_build(plugin)

    user_plugins = base / "user-plugins"
    target = user_plugins / PLUGIN_FOLDER
    backups = base / "plugin-backups"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    user_plugins.mkdir(parents=True, exist_ok=True)

    # Stage next to user-plugins (same disk, so the final rename is atomic) but outside it,
    # so Headlamp never sees a half-copied plugin.
    staging = Path(tempfile.mkdtemp(prefix=".kubescape-install-", dir=base))
    previous = None
    # the folders moved to the backups, to put back when the install fails
    moved: list[tuple[Path, Path]] = []
    try:
        shutil.copytree(plugin, staging / PLUGIN_FOLDER)
        for other in other_kubescape_folders(base, target):
            dest = move_to_backup(other, backups, f"{other.parent.name}-{other.name}-{stamp}")
            moved.append((other, dest))
            log(f"Moved {other} to {dest} (only one Kubescape plugin can be installed)")
        if target.exists():
            previous = move_to_backup(target, backups, f"{PLUGIN_FOLDER}-{stamp}")
            moved.append((target, previous))
        os.replace(staging / PLUGIN_FOLDER, target)
    except (OSError, shutil.Error) as error:
        # Headlamp keeps the plugin it had
        for original, backup in reversed(moved):
            if backup.exists() and not original.exists():
                try:
                    shutil.move(str(backup), str(original))
                except OSError:
                    log(f"Could not put {backup} back at {original}")
        hint = "\nClose Headlamp and run the installer again." if isinstance(error, PermissionError) else ""
        raise InstallError(f"Installing failed: {error}{hint}") from None
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
    parser.add_argument(
        "--verify-attestation",
        action="store_true",
        help="check with the GitHub CLI that the release workflow built the downloaded archive",
    )
    parser.add_argument("--headlamp-dir", type=Path, metavar="PATH", help="Headlamp data folder (default: detected)")
    parser.add_argument(
        "--output",
        type=Path,
        metavar="DIR",
        help="copy the plugin into DIR (its contents are replaced) instead of installing it into Headlamp desktop",
    )
    args = parser.parse_args(argv)
    if args.output and (args.uninstall or args.headlamp_dir):
        parser.error("--output cannot be combined with --uninstall or --headlamp-dir")

    base = args.headlamp_dir or headlamp_dir()
    if not args.output:
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
                plugin = build(copy_checkout(args.source.resolve(), work), work)
            elif args.build:
                plugin = build(download_source(args.repo, args.ref, work), work)
            else:
                plugin = download_release(args.repo, args.tag, work, args.verify_attestation)
            target = write_output(plugin, args.output) if args.output else install(plugin, base)
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

    if args.output:
        log(f"Built {PACKAGE_NAME} {version} in {target}")
        return 0
    log(f"Installed {PACKAGE_NAME} {version} in {target}")
    log("Restart Headlamp to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
