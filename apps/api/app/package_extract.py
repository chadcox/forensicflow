"""Extract uploaded evidence archives (handles ZIP compression Python zipfile cannot)."""

import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class PackageExtractError(Exception):
    """User-facing extraction failure."""


def _member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def is_supported_archive(path_or_name: Path | str) -> bool:
    name = str(path_or_name).lower()
    return name.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def _normalize_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def _validate_member_name(name: str) -> None:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if PurePosixPath(normalized).is_absolute() or normalized.startswith(("/", "\\")):
        raise PackageExtractError(f"Archive contains an absolute path: {name}")
    normalized = normalized.rstrip("/")
    if normalized in ("", "."):
        return
    path = PurePosixPath(normalized)
    if any(part in ("", ".", "..") for part in path.parts):
        raise PackageExtractError(f"Archive contains an unsafe path: {name}")
    if len(normalized) > 4096:
        raise PackageExtractError(f"Archive path is too long: {name[:120]}")


def _validate_zip(
    zf: zipfile.ZipFile,
    *,
    max_files: int,
    max_uncompressed_bytes: int,
) -> None:
    file_count = 0
    total_size = 0
    for info in zf.infolist():
        _validate_member_name(info.filename)
        if info.flag_bits & 0x1:
            raise PackageExtractError(
                "ZIP is password-protected/encrypted. "
                "Decrypt it and re-upload as a standard (unencrypted) ZIP."
            )
        if _member_is_symlink(info):
            raise PackageExtractError(f"Archive contains a symlink entry: {info.filename}")
        if info.is_dir():
            continue
        file_count += 1
        if file_count > max_files:
            raise PackageExtractError(f"Archive contains more than {max_files:,} files")
        total_size += max(0, info.file_size)
        if total_size > max_uncompressed_bytes:
            raise PackageExtractError(
                f"Archive expands beyond the configured limit of {max_uncompressed_bytes:,} bytes"
            )


def _extract_zipfile_safely(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_root = dest.resolve()
    for info in zf.infolist():
        member_name = _normalize_member_name(info.filename)
        if member_name in ("", "."):
            continue
        target = (dest / member_name).resolve()
        try:
            target.relative_to(dest_root)
        except ValueError as exc:
            raise PackageExtractError(f"Archive path escapes destination: {info.filename}") from exc

        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, target.open("wb") as out:
            shutil.copyfileobj(src, out)


def _validate_extracted_tree(
    dest: Path,
    *,
    max_files: int,
    max_uncompressed_bytes: int,
) -> None:
    dest_root = dest.resolve()
    file_count = 0
    total_size = 0
    for root, dirnames, filenames in os.walk(dest):
        root_path = Path(root).resolve()
        try:
            root_path.relative_to(dest_root)
        except ValueError as exc:
            raise PackageExtractError("Archive extraction escaped destination") from exc

        for dirname in dirnames:
            path = root_path / dirname
            if path.is_symlink():
                raise PackageExtractError(f"Archive extracted a symlink directory: {path.name}")

        for filename in filenames:
            path = root_path / filename
            if path.is_symlink():
                raise PackageExtractError(f"Archive extracted a symlink file: {path.name}")
            file_count += 1
            if file_count > max_files:
                raise PackageExtractError(f"Archive extracted more than {max_files:,} files")
            try:
                total_size += path.stat().st_size
            except OSError:
                continue
            if total_size > max_uncompressed_bytes:
                raise PackageExtractError(
                    f"Archive extracted beyond the configured limit of {max_uncompressed_bytes:,} bytes"
                )


def _validate_tar(
    tf: tarfile.TarFile,
    *,
    max_files: int,
    max_uncompressed_bytes: int,
) -> None:
    file_count = 0
    total_size = 0
    for info in tf.getmembers():
        _validate_member_name(info.name)
        if info.isdir():
            continue
        if info.issym() or info.islnk():
            continue
        if not info.isfile():
            raise PackageExtractError(f"Archive contains an unsupported entry: {info.name}")
        file_count += 1
        if file_count > max_files:
            raise PackageExtractError(f"Archive contains more than {max_files:,} files")
        total_size += max(0, info.size)
        if total_size > max_uncompressed_bytes:
            raise PackageExtractError(
                f"Archive expands beyond the configured limit of {max_uncompressed_bytes:,} bytes"
            )


def _extract_tarfile_safely(tf: tarfile.TarFile, dest: Path) -> None:
    dest_root = dest.resolve()
    for info in tf.getmembers():
        member_name = _normalize_member_name(info.name)
        if member_name in ("", "."):
            continue
        target = (dest / member_name).resolve()
        try:
            target.relative_to(dest_root)
        except ValueError as exc:
            raise PackageExtractError(f"Archive path escapes destination: {info.name}") from exc

        if info.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if info.issym() or info.islnk():
            # UAC packages can include many filesystem links; ignore them so
            # one link does not fail the whole collection import.
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(info)
        if src is None:
            raise PackageExtractError(f"Archive member could not be read: {info.name}")
        with src, target.open("wb") as out:
            shutil.copyfileobj(src, out)


def extract_zip(
    archive_path: Path,
    dest: Path,
    *,
    max_files: int = 250_000,
    max_uncompressed_bytes: int = 500 * 1024 * 1024 * 1024,
) -> None:
    """Extract ZIP to dest; fall back to system unzip for Deflate64 / uncommon methods."""
    dest.mkdir(parents=True, exist_ok=True)

    zip_err: Exception | None = None
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            _validate_zip(
                zf,
                max_files=max_files,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            _extract_zipfile_safely(zf, dest)
        return
    except NotImplementedError as exc:
        zip_err = exc
    except zipfile.BadZipFile as exc:
        raise PackageExtractError(f"Invalid ZIP file: {exc}") from exc

    if shutil.which("unzip") is None:
        raise PackageExtractError(
            "ZIP uses an unsupported compression method. "
            "Re-export as standard ZIP (Deflate) or contact your admin."
        ) from zip_err

    result = subprocess.run(
        ["unzip", "-q", "-o", str(archive_path), "-d", str(dest)],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise PackageExtractError(
            detail
            or "Could not extract ZIP. Try re-zipping with standard Deflate compression."
        ) from zip_err

    _validate_extracted_tree(
        dest,
        max_files=max_files,
        max_uncompressed_bytes=max_uncompressed_bytes,
    )


def extract_tar(
    archive_path: Path,
    dest: Path,
    *,
    max_files: int = 250_000,
    max_uncompressed_bytes: int = 500 * 1024 * 1024 * 1024,
) -> None:
    """Extract TAR/TAR.GZ/TGZ to dest with traversal, link, count, and size checks."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            _validate_tar(
                tf,
                max_files=max_files,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            _extract_tarfile_safely(tf, dest)
    except tarfile.TarError as exc:
        raise PackageExtractError(f"Invalid TAR file: {exc}") from exc

    _validate_extracted_tree(
        dest,
        max_files=max_files,
        max_uncompressed_bytes=max_uncompressed_bytes,
    )


def extract_archive(
    archive_path: Path,
    dest: Path,
    *,
    max_files: int = 250_000,
    max_uncompressed_bytes: int = 500 * 1024 * 1024 * 1024,
) -> None:
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        extract_zip(
            archive_path,
            dest,
            max_files=max_files,
            max_uncompressed_bytes=max_uncompressed_bytes,
        )
        return
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        extract_tar(
            archive_path,
            dest,
            max_files=max_files,
            max_uncompressed_bytes=max_uncompressed_bytes,
        )
        return
    raise PackageExtractError("Unsupported archive type")
