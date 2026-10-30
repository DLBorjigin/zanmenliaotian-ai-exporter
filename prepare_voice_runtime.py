from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "wechat-ai-exporter-release-builder/1.0.7"


def _hash(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    if destination.is_file():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response, \
         destination.open("xb") as output:
        shutil.copyfileobj(response, output)


def _verify(path: Path, expected: str, algorithm: str = "sha256") -> None:
    actual = _hash(path, algorithm)
    if actual.casefold() != expected.casefold():
        raise RuntimeError(f"Checksum mismatch for {path.name}: {actual}")


def _run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=300)
    if result.returncode:
        raise RuntimeError(f"Build step failed: {Path(command[0]).name}\n{result.stderr[-2000:]}")


def build(cache: Path, output: Path, gcc: Path, make: Path) -> Path:
    config = json.loads((PROJECT_ROOT / "vendor" / "voice-runtime.json").read_text("utf-8"))
    downloads = cache / "downloads"
    whisper_zip = downloads / "whisper-bin-x64.zip"
    model = downloads / config["model"]["name"]
    silk_zip = downloads / "silk-v3-decoder.zip"
    for item, destination in (
        (config["whisper_cpp"], whisper_zip),
        (config["model"], model),
        (config["silk_decoder"], silk_zip),
    ):
        _download(item["url"], destination)
        _verify(destination, item["sha256"])
    _verify(model, config["model"]["sha1"], "sha1")

    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")
    with tempfile.TemporaryDirectory(prefix="wechat-voice-build-") as temporary:
        work = Path(temporary)
        with zipfile.ZipFile(whisper_zip) as archive:
            archive.extractall(work / "whisper")
        with zipfile.ZipFile(silk_zip) as archive:
            archive.extractall(work / "silk-source")
        silk_root = next((work / "silk-source").iterdir())
        silk = silk_root / "silk"
        compiler_dir = gcc.resolve().parent
        variables = [
            f"CC={gcc.resolve().as_posix()}",
            f"CXX={(compiler_dir / 'g++.exe').as_posix()}",
            f"AR={(compiler_dir / 'ar.exe').as_posix()}",
            f"RANLIB={(compiler_dir / 'ranlib.exe').as_posix()}",
            "CFLAGS=-Wall -O3 -Iinterface -Isrc -Itest",
        ]
        _run([str(make.resolve()), "lib", *variables], silk)
        decoder_object = work / "Decoder.o"
        _run([
            str(gcc.resolve()), "-c", str(silk / "test" / "Decoder.c"),
            "-I", str(silk / "interface"), "-I", str(silk / "src"),
            "-I", str(silk / "test"), "-O3", "-o", str(decoder_object),
        ], work)
        decoder = work / "silk-decoder.exe"
        _run([
            str(gcc.resolve()), str(decoder_object), "-L", str(silk),
            "-lSKP_SILK_SDK", "-static", "-o", str(decoder),
        ], work)

        (output / "whisper").mkdir(parents=True)
        release = work / "whisper" / "Release"
        shutil.copy2(release / "whisper-cli.exe", output / "whisper")
        for library in release.glob("*.dll"):
            if library.name.startswith("ggml") or library.name == "whisper.dll":
                shutil.copy2(library, output / "whisper")
        (output / "models").mkdir()
        shutil.copy2(model, output / "models" / model.name)
        (output / "silk").mkdir()
        shutil.copy2(decoder, output / "silk" / decoder.name)
        licenses = output / "licenses"
        licenses.mkdir()
        license_urls = {
            "LICENSE-whisper.cpp.txt": (
                "https://raw.githubusercontent.com/ggml-org/whisper.cpp/"
                + config["whisper_cpp"]["commit"] + "/LICENSE"
            ),
            "LICENSE-openai-whisper-model.txt": (
                "https://raw.githubusercontent.com/openai/whisper/"
                "86098128c0b4f24f0e2aa2994de830614b474227/LICENSE"
            ),
        }
        for name, url in license_urls.items():
            _download(url, licenses / name)
        shutil.copy2(silk_root / "LICENSE", licenses / "LICENSE-silk-v3-decoder.txt")
        decoder_source = (silk / "test" / "Decoder.c").read_text("utf-8")
        notice = decoder_source[:decoder_source.index("*/") + 2] + "\n"
        (licenses / "LICENSE-SILK-SDK.txt").write_text(notice, encoding="utf-8")

    files = {
        path.relative_to(output).as_posix(): {
            "size": path.stat().st_size,
            "sha256": _hash(path),
        }
        for path in sorted(output.rglob("*")) if path.is_file()
    }
    (output / "runtime-manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "offline_only": True,
        "engine": "whisper.cpp",
        "model": "ggml-base multilingual",
        "source_manifest": config,
        "files": files,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gcc", required=True, type=Path)
    parser.add_argument("--make", required=True, type=Path)
    arguments = parser.parse_args()
    print(build(arguments.cache.resolve(), arguments.output.resolve(),
                arguments.gcc, arguments.make))
