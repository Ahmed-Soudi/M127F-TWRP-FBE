#!/usr/bin/env python3
"""Offline fix14 regressions against pinned source and a recording HIDL HAL."""

import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
HAT_PATCH_SHA256 = "efb7fd94b9a18df506fd14e24d55ebf165521e71e5e564c0108fa78c873e9507"
EXPECTED_BLOBS = {
    "Keymaster.cpp": "c3c230c793501db721854c11082a361980e05955",
    "Keymaster.h": "0e4d01a00081b31e2fb469cf203933cb70764b0a",
    "KeyStorage.cpp": "d1f4203c82169853041b82fa8f0a3f2ccd2749a8",
}


def load_patch(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "source" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def original_sources():
    result = {name: (FIXTURES / name).read_text() for name in EXPECTED_BLOBS}
    # Apply the unchanged v21 CE/HAT baseline before the narrowly scoped fix14.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "KeyStorage.cpp"
        path.write_text(result["KeyStorage.cpp"])
        load_patch("patch_v21").patch_keystorage_cpp(Path(tmp))
        result["KeyStorage.cpp"] = path.read_text()
    return result


def cpp_functions(source, prefix):
    """Extract complete functions, ignoring braces in strings and comments."""
    ignored = r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    masked = re.sub(ignored, lambda match: " " * len(match[0]), source)
    functions = []
    at = 0
    while True:
        start = source.find(prefix, at)
        if start < 0:
            return functions
        body_start = masked.index("{", start)
        depth = 1
        end = body_start + 1
        while depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        functions.append(source[start:end])
        at = end


class StorageKeyPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patch = load_patch("fix_v21_storage_key_compat")
        cls.original = original_sources()

    def test_exact_upstream_fixtures_and_original_hat_patch_are_preserved(self):
        for name, expected in EXPECTED_BLOBS.items():
            content = (FIXTURES / name).read_bytes()
            digest = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            with self.subTest(source=name):
                self.assertEqual(digest, expected)
        self.assertEqual(hashlib.sha256((ROOT / "source" / "patch_v21.py").read_bytes()).hexdigest(), HAT_PATCH_SHA256)

    def test_patch_is_idempotent_and_original_begin_overloads_are_byte_identical(self):
        patched = self.patch.patch_sources(self.original)
        self.assertEqual(self.patch.patch_sources(patched), patched)
        for name, text in self.original.items():
            with self.subTest(inferred_source=name):
                self.assertEqual(self.patch.patch_source(text), patched[name])
        baseline_begin = cpp_functions(self.original["Keymaster.cpp"], "KeymasterOperation Keymaster::begin(")
        patched_begin = cpp_functions(patched["Keymaster.cpp"], "KeymasterOperation Keymaster::begin(")
        self.assertEqual(len(baseline_begin), 2)
        self.assertEqual(patched_begin, baseline_begin)
        self.assertEqual(cpp_functions(patched["Keymaster.cpp"], "bool Keymaster::upgradeKey("),
                         cpp_functions(self.original["Keymaster.cpp"], "bool Keymaster::upgradeKey("))
        before = self.original["KeyStorage.cpp"]
        after = patched["KeyStorage.cpp"]
        auth_start = "    if (auth != nullptr && !auth->token.empty()) {"
        auth_end = "    } else {"
        self.assertEqual(after[after.index(auth_start):after.index(auth_end, after.index(auth_start))],
                         before[before.index(auth_start):before.index(auth_end, before.index(auth_start))])
        # Encryption, CE appId derivation and user-key retrieval keep their code.
        tail = "static bool encryptWithKeymasterKey("
        self.assertEqual(after[after.index(tail):], before[before.index(tail):])

    def test_ambiguous_partial_or_unsupported_sources_fail_without_mutating_inputs(self):
        patched = self.patch.patch_sources(self.original)
        cases = [
            {**self.original, "Keymaster.cpp": self.original["Keymaster.cpp"] * 2},
            {**self.original, "KeyStorage.cpp": self.original["KeyStorage.cpp"] * 2},
            {**self.original, "Keymaster.h": "unsupported header"},
            {**patched, "Keymaster.cpp": patched["Keymaster.cpp"] + self.original["Keymaster.cpp"]},
            {**patched, "KeyStorage.cpp": patched["KeyStorage.cpp"] + self.original["KeyStorage.cpp"]},
            {**patched, "Keymaster.cpp": patched["Keymaster.cpp"].replace(self.patch.CPP_METHOD,
                self.patch.CPP_METHOD.replace("\n", "\n/* partial patch */\n", 1), 1)},
        ]
        for sources in cases:
            before = dict(sources)
            with self.subTest(lengths={name: len(text) for name, text in sources.items()}):
                with self.assertRaises(ValueError):
                    self.patch.patch_sources(sources)
                self.assertEqual(sources, before)

    def test_cli_validates_every_file_before_writing_any_file(self):
        for failing_file in self.original:
            with self.subTest(failing_file=failing_file), tempfile.TemporaryDirectory() as tmp:
                paths = {}
                for name, text in self.original.items():
                    path = Path(tmp) / name
                    path.write_text(text if name != failing_file else text * 2)
                    paths[name] = path
                before = {name: path.read_bytes() for name, path in paths.items()}
                result = subprocess.run([sys.executable, str(ROOT / "source" / "fix_v21_storage_key_compat.py"), tmp], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual({name: path.read_bytes() for name, path in paths.items()}, before)

    def test_cli_applies_all_three_files_and_second_apply_preserves_bytes_modes_and_times(self):
        expected = self.patch.patch_sources(self.original)
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, text in self.original.items():
                paths[name] = Path(tmp) / name
                paths[name].write_text(text)
                paths[name].chmod(0o640)
            command = [sys.executable, str(ROOT / "source" / "fix_v21_storage_key_compat.py"), tmp]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({name: path.read_text() for name, path in paths.items()}, expected)
            before = {name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for name, path in paths.items()}
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("already applied", result.stdout)
            self.assertEqual({name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for name, path in paths.items()}, before)
            self.assertEqual(sorted(path.name for path in Path(tmp).iterdir()), sorted(self.original))

    def test_later_publish_failure_restores_every_original_and_cleans_staging_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in self.original.items():
                (root / name).write_text(text)
                (root / name).chmod(0o640)
            before = {name: ((root / name).read_bytes(), (root / name).stat().st_mode) for name in self.original}
            replace = self.patch.os.replace
            calls = []

            def fail_second_publish(source, target):
                calls.append((source, target))
                if len(calls) == 2:
                    raise OSError("synthetic second-file publication failure")
                return replace(source, target)

            with mock.patch.object(self.patch.os, "replace", side_effect=fail_second_publish):
                with self.assertRaises(OSError):
                    self.patch.apply_patch(root)
            self.assertGreaterEqual(len(calls), 3)  # First publish, failure, rollback.
            self.assertEqual({name: ((root / name).read_bytes(), (root / name).stat().st_mode) for name in self.original}, before)
            self.assertEqual(sorted(path.name for path in root.iterdir()), sorted(self.original))

    def test_runtime_diagnostics_are_selected_by_existing_capture_filter(self):
        # The previously supplied external-capture script selects this pattern.
        selected = re.compile(r"v21:.*(metadata|crypto)", re.IGNORECASE)
        diagnostics = re.findall(r'"(v21:[^"\n]*)"', self.patch.CPP_METHOD)
        self.assertGreaterEqual(len(diagnostics), 8)
        for message in diagnostics:
            with self.subTest(message=message):
                self.assertRegex(message, selected)


@unittest.skipUnless(shutil.which("g++"), "g++ is required for HIDL behavioral tests")
class StorageKeyBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = load_patch("fix_v21_storage_key_compat")
        originals = original_sources()
        patched = patch.patch_sources(originals)
        # Compile the production new method, unchanged original begin overloads,
        # and unchanged original upgradeKey against a HAL that records requests.
        methods = cpp_functions(originals["Keymaster.cpp"], "bool Keymaster::upgradeKey(")
        methods += cpp_functions(originals["Keymaster.cpp"], "KeymasterOperation Keymaster::begin(")
        methods.append(patch.CPP_METHOD)
        source = '#include "storage_key_stubs.hpp"\nnamespace android { namespace vold {\n'
        source += "\n\n".join(methods) + "\n" + patch.CPP_SCOPE
        # Reuse the actual patched auth/else dispatch block, with no file IO.
        storage = patched["KeyStorage.cpp"]
        start = storage.index("    KeymasterOperation opHandle;", storage.index("static KeymasterOperation BeginKeymasterOp("))
        end = storage.index('    printf("[DEBUG] BeginKeymasterOp: keymaster.begin() returned', start)
        source += '''
KeymasterOperation route_key(Keymaster& keymaster, const std::string& dir,
        const std::string& blob, const km::AuthorizationSet& inParams,
        km::AuthorizationSet* outParams, const KeyAuthentication* auth) {
'''
        source += storage[start:end] + "\nreturn opHandle;\n}\n} }\n"
        source += r'''
using namespace android::vold;

static std::string raw_key() {
    std::string key(538, '\0');
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<char>(i % 251);
    return key;
}
static std::string wrapped_key(const std::string& raw) {
    return std::string("pKMblob", 7) + std::string(1, '\0') + raw;
}
static km::AuthorizationSet parameters(bool application_data = true) {
    km::AuthorizationSet result;
    result.push_back({km::Tag::PURPOSE, {2}});
    result.push_back({km::Tag::APPLICATION_ID, std::vector<uint8_t>(64, 0xa1)});
    result.push_back({km::Tag::NONCE, std::vector<uint8_t>(12, 0xb2)});
    result.push_back({km::Tag::BLOCK_MODE, {3}});
    if (application_data) result.push_back({km::Tag::APPLICATION_DATA, {0, 1, 0xff, 2}});
    result.push_back({km::Tag::PADDING, {4}});
    result.push_back({km::Tag::OS_VERSION, {0x13}});
    result.push_back({km::Tag::OS_PATCHLEVEL, {0x26}});
    return result;
}
static void assert_upgrade_binding(const FakeHAL& hal, const km::AuthorizationSet& params) {
    assert(hal.upgrades.size() == 1);
    km::AuthorizationSet expected;
    expected.push_back(params[1]);
    if (params.size() == 8) expected.push_back(params[4]);
    assert(hal.upgrades[0].parameters == expected);
}
static void assert_empty_auth(const FakeHAL& hal) {
    for (const auto& record : hal.begins) {
        assert(record.token.challenge == 0 && record.token.mac.empty());
        assert(record.purpose == km_hidl::KeyPurpose::DECRYPT);
    }
}
int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string scenario = argv[1];
    auto hal = std::make_shared<FakeHAL>();
    Keymaster keymaster(hal);
    const auto raw = raw_key(), wrapped = wrapped_key(raw);
    assert(raw.size() == 538 && wrapped.size() == 546);
    const auto params = parameters();
    km::AuthorizationSet output;
    if (scenario == "hardware-wrapper" || scenario == "raw-legacy") {
        const auto stored = scenario == "hardware-wrapper" ? wrapped : raw;
        const auto original = stored;
        auto operation = keymaster.beginForDeStorage(stored, params, &output);
        assert(operation && !operation.getUpgradedBlob());
        assert(stored == original);
        assert(hal->begins.size() == 1 && hal->begins[0].blob == raw);
        assert(hal->begins[0].parameters == params && output == hal->output);
        assert(hal->upgrades.empty());
        assert_empty_auth(*hal);
    } else if (scenario == "invalid-wrappers") {
        std::vector<std::string> invalid = {"", "pKMblob", std::string("pKMblob\0", 8),
            std::string("pKMblob\1", 8) + raw, std::string("pKMblob\2", 8) + raw,
            std::string("pKMblob\xff", 8) + raw};
        for (size_t n = 1; n < 7; ++n) invalid.push_back(std::string("pKMblob", n));
        for (const auto& stored : invalid) {
            auto operation = keymaster.beginForDeStorage(stored, params, &output);
            assert(!operation && operation.getErrorCode() == km::ErrorCode::INVALID_KEY_BLOB);
            assert(!operation.getUpgradedBlob());
            assert(hal->begins.empty() && hal->upgrades.empty());
        }
    } else if (scenario == "raw-short-and-nonmarker") {
        for (const auto& stored : std::vector<std::string>{"x", "pQ", "pKMbloX", "legacyKey"}) {
            auto operation = keymaster.beginForDeStorage(stored, params, nullptr);
            assert(operation && hal->begins.back().blob == stored);
        }
        assert(hal->upgrades.empty());
    } else if (scenario == "upgrade-wrapper" || scenario == "upgrade-raw" || scenario == "upgrade-app-id-only") {
        hal->begin_errors = {km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE, km_hidl::ErrorCode::OK};
        hal->upgraded_blob = std::string("new\0synthetic", 13);
        const auto stored = scenario == "upgrade-raw" ? raw : wrapped;
        const auto input_params = parameters(scenario != "upgrade-app-id-only");
        auto operation = keymaster.beginForDeStorage(stored, input_params, &output);
        assert(operation && operation.getUpgradedBlob());
        assert(hal->events == std::vector<std::string>({"begin", "upgrade", "begin"}));
        assert(hal->begins[0].blob == raw && hal->upgrades[0].blob == raw);
        assert(hal->begins[1].blob == hal->upgraded_blob);
        assert(hal->begins[0].parameters == input_params && hal->begins[1].parameters == input_params);
        assert_upgrade_binding(*hal, input_params);
        const auto scratch = scenario == "upgrade-raw" ? hal->upgraded_blob : wrapped_key(hal->upgraded_blob);
        assert(*operation.getUpgradedBlob() == scratch);
        assert(output == hal->output);
        assert_empty_auth(*hal);
    } else if (scenario == "invalid-key-no-upgrade") {
        hal->begin_errors = {km_hidl::ErrorCode::INVALID_KEY_BLOB};
        auto operation = keymaster.beginForDeStorage(wrapped, params, &output);
        assert(!operation && operation.getErrorCode() == km::ErrorCode::INVALID_KEY_BLOB);
        assert(hal->events == std::vector<std::string>({"begin"}));
        assert(hal->begins[0].blob == raw && hal->upgrades.empty());
    } else if (scenario == "upgrade-failure" || scenario == "upgrade-transport-failure" || scenario == "empty-upgrade") {
        hal->begin_errors = {km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE};
        if (scenario == "upgrade-failure") hal->upgrade_error = km_hidl::ErrorCode::INVALID_KEY_BLOB;
        if (scenario == "upgrade-transport-failure") hal->upgrade_transport = false;
        if (scenario == "empty-upgrade") hal->upgraded_blob.clear();
        auto operation = keymaster.beginForDeStorage(wrapped, params, &output);
        assert(!operation && !operation.getUpgradedBlob());
        assert(hal->events == std::vector<std::string>({"begin", "upgrade"}));
        assert(hal->begins.size() == 1 && hal->begins[0].blob == raw);
        assert_upgrade_binding(*hal, params);
    } else if (scenario == "second-begin-failure" || scenario == "second-begin-transport-failure" || scenario == "second-begin-still-needs-upgrade") {
        hal->begin_errors = {km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE,
            scenario == "second-begin-still-needs-upgrade" ? km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE : km_hidl::ErrorCode::INVALID_KEY_BLOB};
        if (scenario == "second-begin-transport-failure") hal->begin_transports = {true, false};
        auto operation = keymaster.beginForDeStorage(wrapped, params, &output);
        assert(!operation && !operation.getUpgradedBlob());
        assert(hal->events == std::vector<std::string>({"begin", "upgrade", "begin"}));
        assert(hal->begins.size() == 2 && hal->upgrades.size() == 1);
        assert(hal->begins[1].blob == hal->upgraded_blob);
    } else if (scenario == "first-begin-transport-failure") {
        hal->begin_transports = {false};
        auto operation = keymaster.beginForDeStorage(wrapped, params, &output);
        assert(!operation && operation.getErrorCode() == km::ErrorCode::UNKNOWN_ERROR);
        assert(hal->events == std::vector<std::string>({"begin"}));
        assert(hal->upgrades.empty());
    } else if (scenario == "no-device") {
        Keymaster absent(nullptr);
        auto operation = absent.beginForDeStorage(wrapped, params, &output);
        assert(!operation && operation.getErrorCode() == km::ErrorCode::UNKNOWN_ERROR);
        assert(hal->events.empty());
    } else if (scenario == "directory-routing") {
        const std::vector<std::string> allowed = {"/metadata/vold/metadata_encryption/key", "/data/unencrypted/key",
            "/data/misc/vold/user_keys/de/0", "/data/misc/vold/user_keys/de/12", "/data/misc/vold/user_keys/de/001"};
        for (const auto& path : allowed) {
            auto operation = route_key(keymaster, path, wrapped, params, &output, nullptr);
            assert(operation && hal->begins.back().blob == raw);
            KeyAuthentication empty_authentication;
            auto empty_auth_operation = route_key(keymaster, path, wrapped, params, &output, &empty_authentication);
            assert(empty_auth_operation && hal->begins.back().blob == raw);
        }
        const std::vector<std::string> excluded = {"", "/metadata/vold/metadata_encryption/key/", "/metadata/vold/metadata_encryption/keyevil",
            "/metadata/vold/metadata_encryption/key/../key", "/data/unencrypted/key/", "/data/unencrypted/key_extra",
            "/data/misc/vold/user_keys/de/", "/data/misc/vold/user_keys/de/-1", "/data/misc/vold/user_keys/de/0/",
            "/data/misc/vold/user_keys/de/0/current", "/data/misc/vold/user_keys/de/1.0", "/data/misc/vold/user_keys/de/０",
            "/data/misc/vold/user_keys/ce/0", "/data/misc/vold/user_keys/ce/0/current"};
        for (const auto& path : excluded) {
            auto operation = route_key(keymaster, path, wrapped, params, &output, nullptr);
            assert(operation && hal->begins.back().blob == wrapped);
        }
        assert(hal->upgrades.empty());
    } else if (scenario == "nonempty-hat-bypasses-storage-route") {
        KeyAuthentication authentication{std::string(69, char(0xa7))};
        for (const auto& path : std::vector<std::string>{"/metadata/vold/metadata_encryption/key", "/data/unencrypted/key",
                "/data/misc/vold/user_keys/de/0", "/data/misc/vold/user_keys/ce/0/current"}) {
            auto operation = route_key(keymaster, path, wrapped, params, &output, &authentication);
            assert(operation && hal->begins.back().blob == wrapped);
            assert(hal->begins.back().token.mac == std::vector<uint8_t>(69, 0xa7));
        }
        assert(hal->upgrades.empty());
    } else if (scenario == "invalid-hat-bypasses-storage-route") {
        KeyAuthentication authentication{"bad synthetic token"};
        auto operation = route_key(keymaster, "/metadata/vold/metadata_encryption/key", wrapped, params, &output, &authentication);
        assert(!operation && hal->events.empty());
    } else {
        return 2;
    }
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tmp.name) / "storage-key-test"
        cpp = Path(cls.tmp.name) / "storage-key-test.cpp"
        cpp.write_text(source)
        result = subprocess.run([shutil.which("g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "tests"), str(cpp), "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError("Production Keymaster methods failed to compile:\n" + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hardware_wrapper_removes_exactly_eight_bytes_and_raw_legacy_is_unchanged(self):
        for scenario in ("hardware-wrapper", "raw-legacy", "raw-short-and-nonmarker"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_software_malformed_truncated_and_empty_blobs_never_reach_hal(self):
        self.run_scenario("invalid-wrappers")

    def test_upgrade_preserves_only_application_binding_and_original_scratch_format(self):
        for scenario in ("upgrade-wrapper", "upgrade-raw", "upgrade-app-id-only"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_invalid_key_error_does_not_trigger_upgrade_or_other_offsets(self):
        self.run_scenario("invalid-key-no-upgrade")

    def test_failed_or_empty_upgrade_never_retries_begin(self):
        for scenario in ("upgrade-failure", "upgrade-transport-failure", "empty-upgrade"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_second_begin_failure_does_not_loop_or_return_upgraded_scratch(self):
        for scenario in ("second-begin-failure", "second-begin-transport-failure", "second-begin-still-needs-upgrade"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_missing_hal_or_transport_error_fails_without_upgrade(self):
        for scenario in ("no-device", "first-begin-transport-failure"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_only_exact_metadata_and_numeric_de_paths_use_new_no_auth_method(self):
        self.run_scenario("directory-routing")

    def test_nonempty_hat_and_ce_paths_keep_original_begin_behavior(self):
        for scenario in ("nonempty-hat-bypasses-storage-route", "invalid-hat-bypasses-storage-route"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)


if __name__ == "__main__":
    unittest.main()
