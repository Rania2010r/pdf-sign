#!/usr/bin/env bash
set -euo pipefail

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"

# Non-interactive agent defaults: sequoia-gpg-agent sends OPTION values,
# keep them non-empty even in CI.
export GPG_TTY=/dev/null
export LANG=C

gpgconf --launch gpg-agent

gpg --batch --pinentry-mode loopback --passphrase "" \
  --quick-generate-key "CI Test <ci@example.invalid>" default default never

gpg --batch --armor --export "ci@example.invalid" >cert.asc

cat >input.pdf <<'EOF'
%PDF-1.1
1 0 obj
<<>>
endobj
trailer
<<>>
%%EOF
EOF

signed="$("$PDF_SIGN" sign input.pdf --key cert.asc)"
"$PDF_SIGN" verify "$signed" --cert cert.asc | grep -x OK >/dev/null

if [[ -n "${out:-}" ]]; then
  touch "$out"
fi
