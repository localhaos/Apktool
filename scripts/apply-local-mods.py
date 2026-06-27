#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def replace_once(text: str, needle: str, replacement: str, description: str) -> str:
    count = text.count(needle)
    if count == 0:
        raise RuntimeError(f"Cannot patch Main.java: marker not found: {description}")
    if count > 1:
        raise RuntimeError(f"Cannot patch Main.java: marker is ambiguous: {description} ({count} matches)")
    return text.replace(needle, replacement, 1)


def patch_main_java(root: Path) -> None:
    main_path = root / "brut.apktool" / "apktool-cli" / "src" / "main" / "java" / "brut" / "apktool" / "Main.java"
    if not main_path.exists():
        raise FileNotFoundError(main_path)

    text = main_path.read_text(encoding="utf-8")
    original = text

    if "brut.apktool.extensions.ApkDoctor" not in text:
        if "import java.util.logging.*;" in text:
            text = replace_once(
                text,
                "import java.util.logging.*;",
                "import java.util.logging.*;\nimport brut.apktool.extensions.ApkDoctor;",
                "java.util.logging import",
            )
        else:
            text = replace_once(
                text,
                "import brut.util.OSDetection;",
                "import brut.util.OSDetection;\nimport brut.apktool.extensions.ApkDoctor;",
                "OSDetection import",
            )

    if 'case "doctor"' not in text:
        marker = 'case "pr":\n            case "publicize-resources":'
        if marker in text:
            text = replace_once(
                text,
                marker,
                'case "doctor":\n            case "x-doctor":\n                ApkDoctor.run(cmdArgs);\n                break;\n            case "pr":\n            case "publicize-resources":',
                "publicize-resources switch marker",
            )
        else:
            compact_marker = 'case "pr": case "publicize-resources":'
            text = replace_once(
                text,
                compact_marker,
                'case "doctor": case "x-doctor": ApkDoctor.run(cmdArgs); break; case "pr": case "publicize-resources":',
                "compact publicize-resources switch marker",
            )

    # Pre-decode hook: write original checksums and, only when a conservative magic repair is possible,
    # decode a repaired sidecar APK instead of modifying the source APK.
    if "ApkDoctor.preDecode" not in text:
        marker = 'try { new ApkDecoder(new File(apkName), config).decode(outDir); }'
        replacement = 'try { File effectiveApkFile = ApkDoctor.preDecode(new File(apkName), outDir); new ApkDecoder(effectiveApkFile, config).decode(outDir); }'
        if marker in text:
            text = replace_once(text, marker, replacement, "decode preflight marker")
        else:
            marker_multiline = 'try {\n            new ApkDecoder(new File(apkName), config).decode(outDir);\n        }'
            replacement_multiline = 'try {\n            File effectiveApkFile = ApkDoctor.preDecode(new File(apkName), outDir);\n            new ApkDecoder(effectiveApkFile, config).decode(outDir);\n        }'
            text = replace_once(text, marker_multiline, replacement_multiline, "multiline decode preflight marker")

    if 'apktool doctor|x-doctor' not in text:
        usage_marker = 'writer.println("apktool pr|publicize-resources ");'
        if usage_marker in text:
            text = replace_once(
                text,
                usage_marker,
                'writer.println("apktool doctor|x-doctor [--json] [--fix|--repair] [-o fixed.apk] <apk>"); writer.println(); ' + usage_marker,
                "usage marker",
            )
        # Usage injection is non-critical; skip if upstream changed help formatting.

    if text != original:
        main_path.write_text(text, encoding="utf-8", newline="\n")


def copy_overlay(root: Path, overlay_root: Path) -> None:
    source = overlay_root / "apktool-cli" / "src" / "main" / "java"
    target = root / "brut.apktool" / "apktool-cli" / "src" / "main" / "java"
    if not source.exists():
        raise FileNotFoundError(source)
    for file_path in source.rglob("*.java"):
        relative = file_path.relative_to(source)
        dest = target / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, dest)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: apply-local-mods.py <apktool-source-root>", file=sys.stderr)
        return 2

    root = Path(argv[1]).resolve()
    overlay_root = Path(__file__).resolve().parents[1] / "overlays"

    copy_overlay(root, overlay_root)
    patch_main_java(root)
    print(f"Applied local overlays to: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
