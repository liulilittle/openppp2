#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m unittest tests.tooling.test_runtime_fixture_hashes -v
python3 tools/check_runtime_fixture_hashes.py

case "${1:-hashes}" in
  hashes)
    ;;
  cpp)
    cmake --build build/test --target runtime_snapshot_test
    ./build/test/runtime_snapshot_test
    ;;
  dart)
    (cd android && flutter test test/runtime_snapshot_test.dart)
    ;;
  swift)
    (cd ios/App && swift test --filter RuntimeSnapshotTests)
    ;;
  *)
    echo "usage: $0 [hashes|cpp|dart|swift]" >&2
    exit 2
    ;;
esac
