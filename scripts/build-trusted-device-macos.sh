#!/usr/bin/env bash
# Build this fork for Apple Silicon without Apple or updater signing secrets.
# Prerequisites: Apple Silicon macOS with Xcode Command Line Tools, Rust/rustup,
# and Bun. CI pins Rust 1.99.1 and Bun 1.4.4.
# Usage, from anywhere: bash /path/to/iloader/scripts/build-trusted-device-macos.sh
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo 'This script requires macOS and its SDK to build the native app.' >&2
  exit 1
fi

if [[ "$(uname -m)" != 'arm64' ]]; then
  echo 'This script requires an Apple Silicon host to run the arm64 tests.' >&2
  exit 1
fi

for required_command in bun cargo rustc rustup xcrun codesign ditto shasum git; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Missing build prerequisite: $required_command" >&2
    exit 1
  fi
done
xcrun --find clang >/dev/null

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
build_target='aarch64-apple-darwin'
export CARGO_TARGET_DIR="$project_dir/src-tauri/target"
bundle_dir="$CARGO_TARGET_DIR/$build_target/release/bundle"
output_dir="$CARGO_TARGET_DIR/trusted-device-artifacts"

# A development build must not import signing identities or submit to Apple,
# even if a developer's shell normally exports credentials for other projects.
unset APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_ID APPLE_PASSWORD
unset APPLE_TEAM_ID APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_PATH
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD
export APPLE_SIGNING_IDENTITY='-'

rustup target add "$build_target"
bun install --frozen-lockfile

# These local unit tests do not contact Apple or need an account or phone.
cargo test --release --locked --manifest-path src-tauri/Cargo.toml \
  -p isideload --lib --target "$build_target"

# Remove generated bundles only, so a renamed app cannot be mistaken for the
# result of this build. Keep compiled dependencies for the next invocation.
rm -rf "$bundle_dir"
bun tauri build --target "$build_target" --bundles app,dmg \
  --config src-tauri/ci.conf.json -- --locked

shopt -s nullglob
app_bundles=("$bundle_dir/macos/"*.app)
dmg_bundles=("$bundle_dir/dmg/"*.dmg)
if [[ ${#app_bundles[@]} -ne 1 || ${#dmg_bundles[@]} -ne 1 ]]; then
  echo 'Expected exactly one freshly built app bundle and one DMG.' >&2
  exit 1
fi
app_bundle="${app_bundles[0]}"
dmg_bundle="${dmg_bundles[0]}"

codesign --verify --deep --strict --verbose=2 "$app_bundle"
app_executable="$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$app_bundle/Contents/Info.plist")"
app_architectures="$(xcrun lipo -archs "$app_bundle/Contents/MacOS/$app_executable")"
if [[ "$app_architectures" != 'arm64' ]]; then
  echo "Unexpected application architecture: $app_architectures" >&2
  exit 1
fi

mkdir -p "$output_dir"
app_zip="$output_dir/iloader-trusted-device-macos-arm64.app.zip"
dmg_output="$output_dir/iloader-trusted-device-macos-arm64.dmg"
rm -f "$app_zip"
ditto -c -k --sequesterRsrc --keepParent "$app_bundle" "$app_zip"
cp "$dmg_bundle" "$dmg_output"

{
  echo 'iloader trusted-device development build'
  echo "Source commit: $(git rev-parse HEAD)"
  echo "Target: $build_target"
  echo 'Signature: ad hoc; not Apple-notarized'
  echo 'Tests: vendored isideload library unit tests passed'
  echo 'Updater artifacts: disabled by src-tauri/ci.conf.json'
  echo "Built at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  bun --version
  cargo --version
  rustc --version
  sw_vers
} > "$output_dir/build-info.txt"

(
  cd "$output_dir"
  shasum -a 256 \
    iloader-trusted-device-macos-arm64.app.zip \
    iloader-trusted-device-macos-arm64.dmg \
    build-info.txt > SHA256SUMS
)

echo "Downloads are ready in $output_dir"
