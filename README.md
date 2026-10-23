# iloader Trusted Device — unofficial fork

A personal fork of [iloader](https://github.com/nab138/iloader) v2.4.0 that uses **trusted Apple devices for two-factor authentication** and disables the SMS route. It targets the `Failed to complete SMS 2FA` / HTTP 403 failure in isideload 0.5.0.

This is an experimental, AI-assisted modification, not an official iloader release or an Apple authentication bypass. You still need the Apple Account password and a valid code from a trusted iPhone, iPad, or Mac signed in to that account. Apple may reject trusted-device authentication too; a successful build does not prove an account can sign in during an outage.

## What changes

- Apple responses that normally select SMS (`secondaryAuth`) request a trusted-device challenge instead. A pending HTTP 409 challenge also requests a fresh device challenge.
- Legacy SMS-send, SMS-verify, and unknown-method states are redirected before dispatch. SMS callbacks are rejected, SMS implementation code is removed, and the SMS HTTP builders fail before constructing a request.
- A rejected trusted-device challenge stops with its HTTP status. An invalid code stays unverified and can be corrected. A successful verification must still complete the normal Apple login.
- The dialog shows verification errors and offers **Send to devices again** and **Cancel**. Three device-code requests per sign-in and the existing fifteen-transition limit bound retries.
- Only one login can own the verification dialog at a time. The response listener is installed before the prompt and removed on completion or timeout.
- Upstream auto-updates are removed. The app uses a separate identifier (`com.voxibanez.iloader.trusted-device`) and Keychain service (`iloader-trusted-device`), so it starts with its own settings and saved credentials.

This does not change the Apple Account's security settings, trusted phone numbers, app-signing limits, anisette providers, or Apple-side availability.

## Download the Mac build

In this repository's **Actions** tab, open a successful **Build trusted-device macOS app** run and download the `iloader-trusted-device-macos-arm64` artifact. It contains:

- `iloader-trusted-device-macos-arm64.dmg`
- `iloader-trusted-device-macos-arm64.app.zip`
- `SHA256SUMS`
- `build-info.txt` with the source commit and toolchain

The app targets **Apple Silicon (arm64)**. It is **ad-hoc signed and not notarized**. No Apple Account credentials or Apple signing secrets are used to build it. The workflow verifies the signature structure and the executable architecture; ad-hoc signing does not confer Apple notarization or developer identity.

Open the DMG and copy **iloader Trusted Device** to Applications, or extract the app ZIP. If macOS asks you to approve the app, use the normal **System Settings → Privacy & Security → Open Anyway** flow after reviewing the source and checksum. Do not disable Gatekeeper globally.

## Sign in and test

1. Open **iloader Trusted Device**. Its subtitle identifies it as an unofficial trusted-device fork.
2. Sign in using the Apple Account already signed in to your trusted iPhone, iPad, or Mac.
3. Approve Apple's sign-in notification on that device and enter its six-digit code in the app.
4. If no code arrives, try **Send to devices again**. If Apple rejects the request, preserve the error text; there is no SMS fallback.
5. After login succeeds, connect/trust your iPhone and use the normal IPA or SideStore installation action.

The fork has separate settings and Keychain entries, so saved logins from the original app will not appear automatically. You can keep both apps installed. Do not share account passwords, verification codes, pairing files, or full authentication logs in public issues.

## Build on an Apple Silicon Mac

Prerequisites: Xcode Command Line Tools, [Rust/rustup](https://rustup.rs/), and [Bun](https://bun.sh/). The GitHub workflow pins Rust **1.99.1** and Bun **1.4.4**. The local script uses the versions installed on your Mac and records them in `build-info.txt`.

From the repository directory:

```bash
bash scripts/build-trusted-device-macos.sh
```

The script installs locked frontend dependencies, runs the vendored authentication library tests, builds the native app and DMG with locked Rust dependencies, verifies the app, and writes downloads to:

```text
src-tauri/target/trusted-device-artifacts/
```

The macOS build requires the macOS SDK and an Apple Silicon host. It cannot be built by this script in a Linux container.

## Development checks

```bash
bun install --frozen-lockfile
bun run build
cargo test --locked --manifest-path src-tauri/Cargo.toml -p isideload --lib
```

The authentication tests use local fixture data and loopback HTTP responses. They do not authenticate to Apple, contact an anisette service, or need a real account. Linux may require the system development libraries used by isideload's dependencies; the macOS workflow is the supported app-build path.

## Source provenance and licensing

- iloader v2.4.0: commit `902597564315442f00ab299dcc758ee0e13b8fa8` from [nab138/iloader](https://github.com/nab138/iloader/tree/v2.4.0).
- Vendored isideload 0.5.0: [published crate](https://crates.io/crates/isideload/0.5.0), source commit `fc7a81a6de678aa707e05399ffafb8be0ad56921`.
- Original crate archive SHA-256: `649ccce64715f7b8f1e9eb330defc48d06d5d35eb8d13d17783533b02c67ba32`.
- The application depends directly on `vendor/isideload`; a registry update cannot silently replace the authentication patch.

Original authors retain their copyrights. The source is MIT-licensed; see `LICENSE` and `vendor/isideload/LICENSE`. Branding is governed by `LICENSE-BRANDING`. Original iloader branding is used with attribution to [the official project](https://github.com/nab138/iloader); this fork is not affiliated with or endorsed by its maintainer. The app's GitHub button continues to link to the official project.
