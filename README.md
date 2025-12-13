# pdf-sign

A lightweight, modern PDF signing utility written in Rust. It creates an Adobe-compatible detached OpenPGP (GPG) signature and appends it to the PDF, making it easy to sign and verify documents without dragging in heavyweight PDF signing stacks.

In practical security terms: many “enterprise PDF signing” solutions pull in a full **CMS/PKCS#7** / **X.509 PKI** toolchain (certificate chains, policy constraints, CRL/OCSP revocation logic, time-stamping/TSAs) plus PDF-form and incremental-update machinery to produce standards like **PAdES**. Those stacks are powerful, but they’re also complex to configure, audit, and automate.

`pdf-sign` intentionally stays on the minimalist end of that spectrum: it produces a detached OpenPGP signature over the PDF bytes and appends it, while delegating all private-key operations to `gpg-agent`.

It’s designed to be a practical alternative to “traditional” PDF signing workflows: minimal setup, scriptable CLI, and it delegates cryptography to your existing `gpg-agent` (including smartcards/YubiKey).

The signed output stays minimal: the original PDF content is preserved and the signature is appended, keeping the file compliant so it still opens normally in standard PDF viewers.

## Features

* **Simple CLI**: `sign` and `verify` commands that compose well in pipelines.
* **Works with your existing GPG setup**: Uses `gpg-agent` (smartcards/YubiKey supported) and reads your local keybox (`pubring.kbx`) for public key lookups.
* **Hardware-friendly**: Private keys can stay on a smartcard/YubiKey.
* **Lightweight distribution**: Single-file script you can run directly (see Quickstart).

## Security model

* **No private keys in the tool**: All signing operations are performed by `gpg-agent`.
* **Reduced key exposure**: Private keys never need to be loaded into this process.
* **Explicit verification**: Verifies using your local keybox by default (no `gpg` subprocess), or a provided certificate via `--cert`.
* **Privacy by default**: Signer UIDs (name/email) are not embedded in the signature unless enabled.

## Quickstart

### Zero-Install Execution

Download the script and execute it. The `nix-shell` shebang will provision dependencies automatically.

```bash
curl -fsSL https://raw.githubusercontent.com/0x77dev/pdf-sign/main/pdf-sign.rs -o pdf-sign.rs
chmod +x pdf-sign.rs
./pdf-sign.rs sign document.pdf --key 0xDEADBEEF
```

### Local Execution

If you already have `pdf-sign.rs` locally, ensure it's executable. The shebang handles the rest.

```bash
chmod +x pdf-sign.rs
./pdf-sign.rs sign input.pdf --key 0xDEADBEEF
```

## Methodology

`pdf-sign` focuses on doing the minimum work needed to connect PDF bytes to `gpg-agent` safely:

1. **PDF Parsing**: Locates the `%%EOF` marker to identify the exact byte range for signing.
2. **Agent Delegation**: Talks to `gpg-agent` (Assuan protocol via `sequoia-gpg-agent`) to perform signing.
3. **Key Isolation**: Your private key stays in `gpg-agent` or on hardware; the tool only handles public material.
4. **Compatibility**: Produces an ASCII-armored detached signature packet and appends it to the PDF for verification.

## Requirements

* **Nix Package Manager**: Used for reproducible, hermetic runtime environment bootstrapping.
* **GnuPG**: A running `gpg-agent`.
* **Public Certificate**: The public key must be importable or available (file or keyring).
* **Private Key**: Managed by `gpg-agent` (Softkey or Smartcard/YubiKey).

## Commands

### Sign

Signs a PDF. Requires a key specification (File path, Key ID, Fingerprint, or Email).

If the input PDF already has appended OpenPGP signatures, `sign` preserves them and appends an additional signature (multi-signer workflow).

```bash
./pdf-sign.rs sign contract.pdf --key 0xF1171FAAAA237211
```

* **--output, -o**: Specify output path (Default: `input_signed.pdf`).
* **--key**: Key spec. If a file path is not found, it falls back to your local keybox (`pubring.kbx`).
* **--embed-uid**: Embed the signer UID into the OpenPGP signature as notation (adds identity metadata).
* **--json**: Output a single JSON object to stdout (useful for scripting).

### Verify

Verifies the appended signature. If `--cert` is omitted, it will look up the signer key in your local keybox (`pubring.kbx`).

If multiple signatures are appended, `verify` checks **all** of them and prints each signer’s details.

```bash
./pdf-sign.rs verify contract_signed.pdf
```

* **--cert, -c**: Optional. Can be provided multiple times. Public certificate file path, fingerprint, key ID, or email.
* **--json**: Output a single JSON object to stdout (useful for scripting).

## Environment

* `GNUPGHOME`: Respected for keybox lookups (defaults to `~/.gnupg`).
* `stderr`: Used for all progress, status, and error reporting.
* `stdout`: Outputs the resulting file path (signing) or "OK" (verification) for pipeline composition.
