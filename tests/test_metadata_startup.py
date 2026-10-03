#!/usr/bin/env python3
"""Offline regressions for metadata startup; no device or network access.

Run with: python3 -m unittest discover -s tests -v
"""

import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
ORIGINAL_CALL = (
    "if (android::vold::fscrypt_mount_metadata_encrypted("
    "Decrypt_Data->Actual_Block_Device, Decrypt_Data->Mount_Point, false, false, "
    "Decrypt_Data->Current_File_System)) {"
)
LEGACY_CALL = ORIGINAL_CALL.replace(
    "Decrypt_Data->Current_File_System))",
    'Decrypt_Data->Current_File_System, "/etc/recovery.fstab"))',
)
LEGACY_WAIT = '''\t\t\tLOGINFO("v21: waiting for crypto services before metadata decrypt\\n");
\t\t\tfor (int i = 0; i < 60; ++i) {
\t\t\t\tconst std::string km = android::base::GetProperty("init.svc.dxj1_keymaster", "");
\t\t\t\tconst std::string gk = android::base::GetProperty("init.svc.dxj1_gatekeeper", "");
\t\t\t\tconst std::string ks = android::base::GetProperty("init.svc.keystore2", "");
\t\t\t\tif (km == "running" && gk == "running" && ks == "running") {
\t\t\t\t\tLOGINFO("v21: crypto services ready after %d ms\\n", i * 250);
\t\t\t\t\tbreak;
\t\t\t\t}
\t\t\t\tif (i == 59) {
\t\t\t\t\tLOGINFO("v21: crypto wait timeout km=%s gk=%s ks=%s\\n",
\t\t\t\t\t\tkm.c_str(), gk.c_str(), ks.c_str());
\t\t\t\t}
\t\t\t\tusleep(250000);
\t\t\t}
'''


def load_patch(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "source" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fixture(name):
    return (FIXTURES / name).read_text()


class PatchSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fstab = load_patch("fix_v21_metadata_fstab")
        cls.wait = load_patch("fix_v21_crypto_wait")
        cls.safety = load_patch("fix_v21_metadata_safety")

    def pipeline(self, source):
        return self.wait.patch_source(self.fstab.patch_source(source))

    def test_fixtures_match_recorded_upstream_snapshots(self):
        expected = {
            "partitionmanager.cpp": "554fa070abe1fb942fe9f464f53bae78bb50c52960a14d12f3db9711fc2c2624",
            "MetadataCrypt.cpp": "f348fadb4f96a0e924611860565fd98b7c80c3ca51fc518300b10a3236a3ee8f",
        }
        for name, digest in expected.items():
            with self.subTest(source=name):
                self.assertEqual(hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), digest)

    def test_pristine_fix11_and_fix12_migrate_to_same_source(self):
        original = fixture("partitionmanager.cpp")
        fix11 = original.replace(ORIGINAL_CALL, LEGACY_CALL)
        fix12 = fix11.replace("\t\t\t" + LEGACY_CALL, LEGACY_WAIT + "\t\t\t" + LEGACY_CALL)
        current = self.pipeline(original)
        self.assertEqual(self.pipeline(fix11), current)
        self.assertEqual(self.pipeline(fix12), current)
        self.assertEqual(self.pipeline(current), current)
        self.assertNotIn('"/etc/recovery.fstab"))', current)
        self.assertNotIn("for (int i = 0; i < 60; ++i)", current)

    def test_user_unlock_and_ce_paths_are_unchanged(self):
        original = fixture("partitionmanager.cpp")
        current = self.pipeline(original)
        ce_start = "\t\tif (Decrypt_Data->Is_FBE) {"
        self.assertEqual(current[current.index(ce_start):], original[original.index(ce_start):])
        for marker in ("captured Gatekeeper HAT", "supplying Gatekeeper HAT", "legacy CE appId"):
            self.assertNotIn(marker, current)

    def test_ambiguous_or_unrecognized_sources_fail_closed(self):
        original = fixture("partitionmanager.cpp")
        cases = ["", original.replace(ORIGINAL_CALL, "if (unexpected_metadata_api()) {"), original + "\n" + ORIGINAL_CALL]
        for source in cases:
            with self.subTest(source_length=len(source)):
                with self.assertRaises(ValueError):
                    self.fstab.patch_source(source)
        patched = self.fstab.patch_source(original)
        for call in (ORIGINAL_CALL, LEGACY_CALL, "if (" + self.fstab.NATIVE_CALL + ") {"):
            with self.subTest(extra_call=call), self.assertRaises(ValueError):
                self.fstab.patch_source(patched + "\n" + call)
        current = self.wait.patch_source(patched)
        for call in (ORIGINAL_CALL, LEGACY_CALL, "if (" + self.fstab.NATIVE_CALL + ") {"):
            with self.subTest(extra_wait_call=call), self.assertRaises(ValueError):
                self.wait.patch_source(current + "\n" + call)

    def test_partial_patches_and_modified_legacy_waits_fail_closed(self):
        original = fixture("partitionmanager.cpp")
        current = self.pipeline(original)
        for module, damaged in (
            (self.fstab, current.replace(self.fstab.CPP_HELPER, self.fstab.CPP_HELPER.replace("\n", "\n/* partial replacement */\n", 1), 1)),
            (self.wait, current.replace(self.wait.CPP_HELPER, self.wait.CPP_HELPER.replace("\n", "\n/* partial replacement */\n", 1), 1)),
            (self.wait, self.fstab.patch_source(original).replace("\t\t\tif (", LEGACY_WAIT.replace("i < 60", "i < 61") + "\t\t\tif (", 1)),
        ):
            with self.subTest(module=module.__name__), self.assertRaises(ValueError):
                module.patch_source(damaged)

    def test_cli_does_not_modify_source_on_anchor_error(self):
        original = fixture("partitionmanager.cpp")
        invalid = original + "\n" + ORIGINAL_CALL
        for script in ("fix_v21_metadata_fstab", "fix_v21_crypto_wait", "fix_v21_metadata_safety"):
            source = invalid if "safety" not in script else fixture("MetadataCrypt.cpp") * 2
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "source.cpp"
                target.write_text(source)
                before = target.read_bytes()
                result = subprocess.run([sys.executable, str(ROOT / "source" / (script + ".py")), str(target)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), before)

    def test_metadata_safety_patch_is_idempotent_and_keeps_other_vold_paths(self):
        original = fixture("MetadataCrypt.cpp")
        current = self.safety.patch_source(original)
        self.assertEqual(self.safety.patch_source(current), current)
        external_volume_start = "static bool get_volume_options(CryptoOptions* options) {"
        self.assertEqual(current[current.index(external_volume_start):], original[original.index(external_volume_start):])
        for duplicated in (original * 2, current * 2, current + original):
            with self.subTest(length=len(duplicated)), self.assertRaises(ValueError):
                self.safety.patch_source(duplicated)


@unittest.skipUnless(shutil.which("g++"), "g++ is required for C++ behavioral tests")
class StartupBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fstab = load_patch("fix_v21_metadata_fstab")
        wait = load_patch("fix_v21_crypto_wait")
        patched = wait.patch_source(fstab.patch_source(fixture("partitionmanager.cpp")))
        call_at = patched.index(fstab.NATIVE_CALL)
        condition_start = patched.rfind("if (", 0, call_at)
        condition_end = patched.index("{", call_at)
        # Compile the actual injected helpers and actual short-circuit condition.
        # Only the clock boundary is redirected to a deterministic fake clock.
        helper = (fstab.CPP_HELPER + wait.CPP_HELPER).replace("std::chrono::steady_clock", "TestClock")
        source = '#include "startup_stubs.hpp"\n' + helper
        source += "\nbool run_metadata() {\n" + patched[condition_start:condition_end]
        source += "{ return true; }\nreturn false;\n}\n"
        source += r'''
int main(int argc, char** argv) {
    assert(argc == 2);
    configure();
    const std::string scenario = argv[1];
    if (scenario == "ready") {
        assert(run_metadata());
        assert(metadata_calls == 1 && sleeps == 0 && binder_releases == 1);
        assert(files.size() == 1);
        assert(files.at("/tmp/v21-metadata.fstab") ==
            "/dev/block/by-name/userdata /data f2fs rw,noatime,nosuid,nodev,inlinecrypt "
            "fileencryption=aes-256-xts:aes-256-cts:v2,"
            "keydirectory=/metadata/vold/metadata_encryption,"
            "metadata_encryption=aes-256-xts\n");
        android::fs_mgr::Fstab parsed;
        assert(android::fs_mgr::ReadFstabFromFile("/tmp/v21-metadata.fstab", &parsed));
        assert(parsed[0].flags == partition.Mount_Flags);
        assert(parsed[0].fs_options == partition.Mount_Options);
    } else if (scenario == "late-registration") {
        // All init properties already say running; binder registration is late.
        ready_after_us = 1000000;
        assert(run_metadata());
        assert(metadata_calls == 1 && sleeps == 4 && elapsed_us == 1000000);
        assert(binder_releases == 1);
    } else if (scenario == "late-managers") {
        managers_ready_after_us = 500000;
        assert(run_metadata());
        assert(metadata_calls == 1 && sleeps == 2 && elapsed_us == 500000);
        assert(service_probes == 3 && binder_releases == 1);
    } else if (scenario == "hardware-manager-not-ready" || scenario == "hardware-manager-stopped" || scenario == "binder-manager-stopped") {
        if (scenario == "hardware-manager-not-ready") properties["hwservicemanager.ready"] = "false";
        if (scenario == "hardware-manager-stopped") properties["init.svc.hwservicemanager"] = "stopped";
        if (scenario == "binder-manager-stopped") properties["init.svc.servicemanager"] = "stopped";
        assert(!run_metadata());
        assert(metadata_calls == 0 && service_probes == 0 && binder_releases == 0);
        assert(sleeps <= 80 && elapsed_us >= 19750000 && elapsed_us <= 20000000);
    } else if (scenario == "keymaster-timeout" || scenario == "gatekeeper-timeout" || scenario == "keystore-timeout") {
        if (scenario == "keymaster-timeout") keymaster_registered = false;
        if (scenario == "gatekeeper-timeout") gatekeeper_registered = false;
        if (scenario == "keystore-timeout") keystore_registered = false;
        assert(!run_metadata());
        assert(metadata_calls == 0);
        assert(sleeps <= 80 && elapsed_us <= 20000000);
        assert(elapsed_us >= 19750000);
        assert(binder_releases == (keystore_registered ? sleeps : 0));
    } else if (scenario == "bad-properties") {
        properties["fbe.filenames"] = "aes-256-cts";
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "unsupported-metadata-flags") {
        properties["metadata.filenames"] = "wrappedkey_v0";
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "wrong-key-directory") {
        partition.Key_Directory = "/metadata/new-key-location";
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "fstab-injection") {
        partition.Actual_Block_Device += "\n/dev/block/evil";
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "mount-option-injection") {
        partition.Mount_Options += ";metadata_encryption=other";
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "read-only") {
        partition.Mount_Read_Only = true;
        assert(run_metadata());
        android::fs_mgr::Fstab parsed;
        assert(android::fs_mgr::ReadFstabFromFile("/tmp/v21-metadata.fstab", &parsed));
        assert(parsed[0].flags == (partition.Mount_Flags | MS_RDONLY));
        assert(parsed[0].fs_options == "inlinecrypt");
        assert(metadata_calls == 1);
    } else if (scenario == "unsupported-mount-flags") {
        partition.Mount_Flags |= (1UL << 31);
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "write-failure") {
        file_write_ok = false;
        assert(!run_metadata() && metadata_calls == 0 && files.empty());
    } else if (scenario == "parser-failure") {
        parser_ok = false;
        assert(!run_metadata() && metadata_calls == 0);
    } else if (scenario == "parser-roundtrip-mismatch") {
        parser_corrupt = true;
        assert(!run_metadata() && metadata_calls == 0);
    } else {
        return 2;
    }
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tmp.name) / "startup-test"
        cpp = Path(cls.tmp.name) / "startup-test.cpp"
        cpp.write_text(source)
        compiled = subprocess.run(
            [shutil.which("g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-DTW_INCLUDE_FBE_METADATA_DECRYPT", "-DUSE_FSCRYPT", "-I", str(ROOT / "tests"), str(cpp), "-o", str(cls.binary)],
            capture_output=True, text=True,
        )
        if compiled.returncode:
            cls.tmp.cleanup()
            raise AssertionError("Injected startup C++ did not compile:\n" + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ready_services_receive_valid_native_fstab(self):
        self.run_scenario("ready")

    def test_running_init_properties_wait_for_registration(self):
        self.run_scenario("late-registration")

    def test_unready_service_managers_are_never_probed(self):
        scenarios = ("hardware-manager-not-ready", "hardware-manager-stopped", "binder-manager-stopped", "late-managers")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_partition_mount_flags_and_read_only_mode_are_preserved(self):
        self.run_scenario("read-only")

    def test_any_missing_registered_service_skips_metadata_after_bounded_wait(self):
        for service in ("keymaster", "gatekeeper", "keystore"):
            with self.subTest(service=service):
                self.run_scenario(service + "-timeout")

    def test_unexpected_configuration_and_fstab_failures_skip_metadata(self):
        scenarios = (
            "bad-properties", "unsupported-metadata-flags", "wrong-key-directory",
            "fstab-injection", "mount-option-injection", "write-failure",
            "parser-failure", "parser-roundtrip-mismatch", "unsupported-mount-flags",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)


@unittest.skipUnless(shutil.which("g++"), "g++ is required for C++ behavioral tests")
class ExistingMetadataKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        safety = load_patch("fix_v21_metadata_safety")
        patched = safety.patch_source(fixture("MetadataCrypt.cpp"))
        start = patched.index("    auto gen = needs_encrypt ? makeGen(options) : neverGen();")
        mapper_at = patched.index("    if (!create_crypto_blk_dev", start)
        end = patched.index("\n    if (needs_encrypt) {", mapper_at)
        # Keep the injected retrieval function and the actual key/mapper block.
        # Fake only the 250ms sleep and the external KeyStorage/mapper APIs.
        helper = safety.CPP_HELPER.replace("std::this_thread::sleep_for", "test_sleep_for")
        source = '#include "metadata_key_stubs.hpp"\n' + helper
        source += '''
bool mount_recovery(const std::string& metadata_dir) {
    const bool needs_encrypt = false;
    DataEntry entry{metadata_dir};
    const auto data_rec = &entry;
    CryptoOptions options;
    const std::string blk_device = "/dev/block/by-name/userdata";
'''
        source += patched[start:end] + "\nreturn true;\n}\n"
        source += r'''
int main(int argc, char** argv) {
    assert(argc == 3);
    const std::string scenario = argv[1], metadata_dir = argv[2];
    if (scenario == "success") {
        assert(mount_recovery(metadata_dir));
        assert(retrieve_attempts == 1 && sleeps == 0 && mapper_calls == 1);
        assert(events == std::vector<std::string>({"retrieve", "mapper"}));
    } else if (scenario == "retry-success") {
        succeed_on_attempt = 3;
        assert(mount_recovery(metadata_dir));
        assert(retrieve_attempts == 3 && sleeps == 2 && mapper_calls == 1);
        assert(events == std::vector<std::string>({"retrieve", "sleep", "retrieve", "sleep", "retrieve", "mapper"}));
    } else if (scenario == "permanent-failure") {
        succeed_on_attempt = 99;
        assert(!mount_recovery(metadata_dir));
        assert(retrieve_attempts == 3 && sleeps == 2 && mapper_calls == 0);
    } else if (scenario == "clear-partial-key") {
        succeed_on_attempt = 99;
        KeyBuffer key = "stale key material";
        assert(!v21_read_existing_metadata_key(metadata_dir, &key));
        assert(key.empty());
        assert(retrieve_attempts == 3 && sleeps == 2 && mapper_calls == 0);
    } else if (scenario == "missing-directory" || scenario == "not-a-directory" || scenario == "empty-directory") {
        const auto path = scenario == "empty-directory" ? "" : metadata_dir;
        KeyBuffer key = "stale key material";
        assert(!v21_read_existing_metadata_key(path, &key));
        assert(key.empty() && retrieve_attempts == 0 && sleeps == 0 && mapper_calls == 0);
        assert(!mount_recovery(path));
        assert(retrieve_attempts == 0 && sleeps == 0 && mapper_calls == 0);
    } else {
        return 2;
    }
    assert(generation_calls == 0);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tmp.name) / "metadata-key-test"
        cpp = Path(cls.tmp.name) / "metadata-key-test.cpp"
        cpp.write_text(source)
        compiled = subprocess.run(
            [shutil.which("g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "tests"), str(cpp), "-o", str(cls.binary)],
            capture_output=True, text=True,
        )
        if compiled.returncode:
            cls.tmp.cleanup()
            raise AssertionError("Injected metadata retrieval C++ did not compile:\n" + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_scenario(self, scenario):
        with tempfile.TemporaryDirectory() as tmp:
            metadata_dir = Path(tmp) / "metadata"
            metadata_dir.mkdir()
            key_dir = metadata_dir / "key"
            key_file = key_dir / "synthetic_key_material"
            if scenario == "not-a-directory":
                key_dir.write_text("synthetic regular file")
            elif scenario != "missing-directory":
                key_dir.mkdir()
                key_file.write_text("synthetic read-only fixture")
                key_file.chmod(0o444)
                key_dir.chmod(0o555)
            try:
                before = key_file.read_bytes() if key_file.is_file() else None
                result = subprocess.run([str(self.binary), scenario, str(metadata_dir)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                if before is not None:
                    self.assertEqual(key_file.read_bytes(), before)
                    self.assertEqual(key_file.stat().st_mode & 0o777, 0o444)
                    self.assertEqual(sorted(p.name for p in key_dir.iterdir()), ["synthetic_key_material"])
                elif scenario == "missing-directory":
                    self.assertFalse(key_dir.exists())
            finally:
                if key_dir.is_dir():
                    key_dir.chmod(0o755)

    def test_existing_read_only_key_succeeds_before_one_mapper_creation(self):
        self.run_scenario("success")

    def test_transient_key_failure_retries_before_creating_mapper(self):
        self.run_scenario("retry-success")

    def test_failed_key_retrieval_never_creates_mapper_and_clears_partial_results(self):
        for scenario in ("permanent-failure", "clear-partial-key"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_missing_or_invalid_existing_key_directory_never_generates_material(self):
        for scenario in ("missing-directory", "not-a-directory", "empty-directory"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)


if __name__ == "__main__":
    unittest.main()
