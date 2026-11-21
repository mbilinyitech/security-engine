import os
import stat

import pytest

from omnishield.hybrid import ReplayError
from omnishield.keystore import FileKeyStore, KeyStoreError, Tpm2KeyStore, open_keystore
from omnishield.replay import ReplayCache


def test_file_roundtrip_and_permissions(tmp_path):
    store = FileKeyStore(tmp_path / "keys")
    store.save("id", b"material")
    assert store.load("id") == b"material"
    assert stat.S_IMODE((tmp_path / "keys").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "keys" / "id.key").stat().st_mode) == 0o600
    assert not list((tmp_path / "keys").glob(".tmp-*"))


def test_loose_file_permissions_refused(tmp_path):
    store = FileKeyStore(tmp_path / "keys")
    store.save("id", b"material")
    os.chmod(tmp_path / "keys" / "id.key", 0o644)
    with pytest.raises(KeyStoreError):
        store.load("id")


def test_loose_directory_permissions_refused(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o755)
    with pytest.raises(KeyStoreError):
        FileKeyStore(directory).save("id", b"material")


@pytest.mark.parametrize("name", ["", "../evil", ".hidden", "a/b"])
def test_invalid_key_names_rejected(tmp_path, name):
    with pytest.raises(KeyStoreError):
        FileKeyStore(tmp_path / "keys").save(name, b"x")


def test_missing_key_reports_error(tmp_path):
    with pytest.raises(KeyStoreError):
        FileKeyStore(tmp_path / "keys").load("nope")


@pytest.mark.skipif(Tpm2KeyStore.available(), reason="TPM present, auto would pick it")
def test_auto_backend_falls_back_to_file(tmp_path):
    assert isinstance(open_keystore("auto", tmp_path / "keys"), FileKeyStore)


@pytest.mark.skipif(Tpm2KeyStore.available(), reason="TPM present")
def test_tpm_backend_refuses_without_device(tmp_path):
    with pytest.raises(KeyStoreError):
        Tpm2KeyStore(tmp_path / "tpm").save("id", b"x")


def test_replay_cache_persists_across_instances(tmp_path):
    path = tmp_path / "replay.json"
    ReplayCache(path).check_and_record(b"k", b"n", 10**15, 1_000)
    with pytest.raises(ReplayError):
        ReplayCache(path).check_and_record(b"k", b"n", 10**15, 1_000)
