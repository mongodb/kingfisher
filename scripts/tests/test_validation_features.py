"""Keep validation all-or-nothing while preserving legacy Cargo manifests."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ValidationFeaturesTests(unittest.TestCase):
    def test_validation_enables_every_optional_provider_dependency(self):
        manifest = tomllib.loads(
            (ROOT / "crates/kingfisher-scanner/Cargo.toml").read_text(encoding="utf-8"))
        features = manifest["features"]
        self.assertEqual(features["default"], [])
        # Offline scanner capabilities have independent optional dependency gates.
        scanning_dependencies = {
            entry for feature in ("context", "archives", "extraction", "git")
            for entry in features[feature] if entry.startswith("dep:")
        }
        dependency_sets = [manifest["dependencies"]]
        dependency_sets.extend(target.get("dependencies", {})
                               for target in manifest.get("target", {}).values())
        for dependencies in dependency_sets:
            for name, specification in dependencies.items():
                if isinstance(specification, dict) and specification.get("optional"):
                    entry = f"dep:{name}"
                    if entry in scanning_dependencies:
                        self.assertNotIn(entry, features["validation"], name)
                    else:
                        self.assertIn(entry, features["validation"], name)

    def test_legacy_features_enable_complete_validation(self):
        features = tomllib.loads(
            (ROOT / "crates/kingfisher-scanner/Cargo.toml").read_text(encoding="utf-8"))["features"]
        for name in ("http", "raw", "grpc", "ethereum", "aws", "azure", "coinbase",
                     "gcp", "jwt", "database", "all"):
            self.assertEqual(features[f"validation-{name}"], ["validation"])
