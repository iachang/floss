#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
REPO_DIR="MOSAC"   # folder name to cd into
ZSHRC="${HOME}/.zshrc"

echo "==> [1/8] Installing dependencies (apt + npm prerequisites)"
sudo apt-get update
sudo apt-get install -y gcc cmake nasm iproute2 npm ninja-build python3

echo "==> [2/8] Installing bazelisk globally via npm"
sudo npm install -g @bazel/bazelisk

echo "==> [3/8] Setting up bazel alias in ~/.zshrc (idempotent)"
if ! grep -q 'alias bazel="bazelisk"' "$ZSHRC" 2>/dev/null; then
  echo 'alias bazel="bazelisk"' >> "$ZSHRC"
  echo "   Added alias to $ZSHRC"
else
  echo "   Alias already present in $ZSHRC"
fi

# Also add for current script execution (no need to source zshrc here)
if command -v bazelisk >/dev/null 2>&1; then
  alias bazel="bazelisk"
fi

echo "==> [4/8] Entering repo directory: $REPO_DIR"
if [[ ! -d "$REPO_DIR" ]]; then
  echo "ERROR: Directory '$REPO_DIR' not found. Run this script from the parent directory of '$REPO_DIR'." >&2
  exit 1
fi
cd "$REPO_DIR"

echo "==> Cleaning bazel state and removing .bazelrc"
bazel clean --expunge || true
rm -f .bazelrc

echo "==> [5/8] Patching WORKSPACE: insert llvm patch_cmds (idempotent)"
python3 - <<'PY'
from pathlib import Path

p = Path("WORKSPACE")
if not p.exists():
    raise SystemExit("ERROR: WORKSPACE file not found in current directory.")

s = p.read_text()

needle = '    strip_prefix = "llvm-project-" + LLVM_COMMIT,\n'

patch_block = needle + (
    '    patch_cmds = [\n'
    '        # Fix missing uintptr_t include for this pinned llvm snapshot\n'
    '        "grep -q \'^#include <cstdint>$\' llvm/include/llvm/Support/Signals.h || '
    'sed -i \'s|^#include <string>$|#include <string>\\\\n#include <cstdint>|\' '
    'llvm/include/llvm/Support/Signals.h",\n'
    '    ],\n'
)

if needle not in s:
    raise SystemExit(
        "ERROR: Could not find the llvm strip_prefix line. "
        "Open WORKSPACE around the llvm-project-raw block and check formatting."
    )

# Don’t double-insert if already present
if "llvm/include/llvm/Support/Signals.h" not in s:
    s = s.replace(needle, patch_block, 1)
    p.write_text(s)
    print("OK: inserted llvm patch_cmds into WORKSPACE")
else:
    print("OK: llvm patch_cmds already present (no change)")
PY

echo "==> [6/8] Patching WORKSPACE: remove TF mirror URL (404) if present"
python3 - <<'PY'
from pathlib import Path

p = Path("WORKSPACE")
s = p.read_text()

target = '    "https://storage.googleapis.com/mirror.tensorflow.org/github.com/llvm/llvm-project/archive/{commit}.tar.gz".format(commit = LLVM_COMMIT),\n'
s2 = s.replace(target, "")

if s2 != s:
    p.write_text(s2)
    print("OK: removed TF mirror URL (404) from WORKSPACE")
else:
    print("OK: TF mirror URL not found (nothing to change)")
PY

echo "==> [7/8] Cleaning bazel and writing .bazelrc"
bazel clean --expunge || true

cat >> .bazelrc <<'RC'
# GCC 13 + msgpack: avoid -Werror=mismatched-new-delete killing the build
build --cxxopt=-Wno-error=mismatched-new-delete
build --cxxopt=-Wno-mismatched-new-delete
# yacl requires C++17 (std::byte, string_view, etc.)
build --cxxopt=-std=c++17
build --host_cxxopt=-std=c++17
# yacl uses cc_shared_library (Bazel 6.x needs this flag)
build --experimental_cc_shared_library
RC

echo "==> [8/8] Building target"
bazel build -c opt //mosac/example:NDSS_online_example --verbose_failures

echo ""
echo "✅ Done."
echo "Note: The 'bazel' alias is in ~/.zshrc; open a new shell or run: source ~/.zshrc"