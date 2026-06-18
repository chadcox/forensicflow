import tarfile
import zipfile
from pathlib import Path

import pytest

from app.package_extract import PackageExtractError, extract_archive, extract_tar, extract_zip


def test_extract_zip_store_method(tmp_path: Path):
    archive = tmp_path / "test.zip"
    dest = tmp_path / "out"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", '{"hostname":"demo"}')

    extract_zip(archive, dest)
    assert (dest / "manifest.json").read_text() == '{"hostname":"demo"}'


def test_extract_tar_gz(tmp_path: Path):
    root = tmp_path / "src" / "uac-linux"
    root.mkdir(parents=True)
    (root / "uac.log").write_text("uac started", encoding="utf-8")
    archive = tmp_path / "uac-linux.tar.gz"
    dest = tmp_path / "out"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname="./uac-linux")

    extract_archive(archive, dest)
    assert (dest / "uac-linux" / "uac.log").read_text() == "uac started"


def test_extract_tar_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "bad.tar.gz"
    dest = tmp_path / "out"
    payload = tmp_path / "payload.txt"
    payload.write_text("bad", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(payload, arcname="../escape.txt")

    with pytest.raises(PackageExtractError, match="unsafe path"):
        extract_tar(archive, dest)

    assert not (tmp_path / "escape.txt").exists()


def test_extract_tar_ignores_symlink_entries(tmp_path: Path):
    archive = tmp_path / "links.tar"
    dest = tmp_path / "out"
    payload = tmp_path / "payload.txt"
    payload.write_text("ok", encoding="utf-8")
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    with tarfile.open(archive, "w") as tf:
        tf.add(payload, arcname="regular.txt")
        tf.addfile(info)

    extract_tar(archive, dest)
    assert (dest / "regular.txt").read_text() == "ok"
    assert not (dest / "link").exists()


def test_extract_zip_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    dest = tmp_path / "out"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("../escape.txt", "bad")

    with pytest.raises(PackageExtractError, match="unsafe path"):
        extract_zip(archive, dest)

    assert not (tmp_path / "escape.txt").exists()


def test_extract_zip_rejects_encrypted(tmp_path: Path):
    import shutil
    import subprocess

    zip_cli = shutil.which("zip")
    if not zip_cli:
        pytest.skip("zip CLI not available to build an encrypted archive")

    (tmp_path / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    archive = tmp_path / "enc.zip"
    subprocess.run(
        [zip_cli, "-q", "-P", "secret123", str(archive), "data.csv"],
        cwd=tmp_path,
        check=True,
    )

    with pytest.raises(PackageExtractError, match="password-protected"):
        extract_zip(archive, tmp_path / "out")


def test_extract_zip_rejects_too_many_files(tmp_path: Path):
    archive = tmp_path / "too-many.zip"
    dest = tmp_path / "out"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", "1")
        zf.writestr("b.txt", "2")

    with pytest.raises(PackageExtractError, match="more than 1"):
        extract_zip(archive, dest, max_files=1)


def test_extract_zip_rejects_expanded_size_limit(tmp_path: Path):
    archive = tmp_path / "too-large.zip"
    dest = tmp_path / "out"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", "12345")

    with pytest.raises(PackageExtractError, match="expands beyond"):
        extract_zip(archive, dest, max_uncompressed_bytes=4)


def test_extract_zip_falls_back_to_unzip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "test.zip"
    dest = tmp_path / "out"
    archive.write_bytes(b"fake")

    def fake_zipfile(*_a, **_k):
        raise NotImplementedError("That compression method is not supported")

    called: list[list[str]] = []

    def fake_unzip(cmd, **kwargs):
        called.append(list(cmd))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "ok.txt").write_text("1")
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("app.package_extract.zipfile.ZipFile", fake_zipfile)
    monkeypatch.setattr("app.package_extract.subprocess.run", fake_unzip)
    monkeypatch.setattr("app.package_extract.shutil.which", lambda _: "/usr/bin/unzip")

    extract_zip(archive, dest)
    assert called
    assert (dest / "ok.txt").is_file()


def test_extract_zip_missing_unzip_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "test.zip"
    dest = tmp_path / "out"
    archive.write_bytes(b"fake")

    def fake_zipfile(*_a, **_k):
        raise NotImplementedError("unsupported")

    monkeypatch.setattr("app.package_extract.zipfile.ZipFile", fake_zipfile)
    monkeypatch.setattr("app.package_extract.shutil.which", lambda _: None)

    with pytest.raises(PackageExtractError, match="unsupported compression"):
        extract_zip(archive, dest)
