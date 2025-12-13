use crate::json::{VerifyJson, VerifySignatureJson};
use crate::keybox::{find_certs_in_keybox, load_cert, load_keybox_certs};
use crate::pdf::{extract_armored_signatures, find_eof_offset};
use crate::util::format_bytes;
use anyhow::{bail, Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::stream::*;
use openpgp::policy::StandardPolicy;
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

struct Helper {
    certs: Vec<Cert>,
    keybox: Option<Vec<Cert>>,
    signer_cert: Rc<RefCell<Option<Cert>>>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        if !self.certs.is_empty() {
            return Ok(self.certs.clone());
        }

        if self.keybox.is_none() {
            let certs = load_keybox_certs()
                .map_err(|e| openpgp::Error::InvalidOperation(e.to_string().into()))?;
            self.keybox = Some(certs);
        }

        let keybox = self.keybox.as_ref().unwrap();

        let mut out = Vec::new();
        for id in ids {
            let spec = match id {
                openpgp::KeyHandle::Fingerprint(fpr) => fpr.to_string(),
                openpgp::KeyHandle::KeyID(kid) => kid.to_string(),
            };
            out.extend(find_certs_in_keybox(keybox, &spec));
        }

        // If the signature doesn't specify issuers (ids empty), or if we couldn't
        // match by issuer, fall back to providing the whole keybox and let
        // Sequoia select the right key during verification.
        if out.is_empty() {
            return Ok(keybox.clone());
        }

        Ok(out)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(good) => {
                            *self.signer_cert.borrow_mut() = Some(good.ka.cert().clone());
                            return Ok(());
                        }
                        Err(e) => return Err(openpgp::Error::from(e).into()),
                    }
                }
            }
        }
        Err(openpgp::Error::InvalidOperation("No valid signature".into()).into())
    }
}

pub(crate) fn verify_pdf(input: PathBuf, cert_spec: Vec<String>, json: bool) -> Result<()> {
    eprintln!("{}", style("==> Verifying PDF signature").cyan().bold());

    // Read signed PDF
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!(
        "Reading signed PDF {}",
        style(input.display()).cyan()
    ));

    let mut signed_data = Vec::new();
    let mut file = BufReader::new(
        File::open(&input)
            .with_context(|| format!("Failed to open signed PDF: {}", input.display()))?,
    );
    file.read_to_end(&mut signed_data)?;

    spinner.finish_with_message(format!(
        "[OK] Read PDF ({})",
        style(format_bytes(signed_data.len())).cyan()
    ));

    let eof_offset = find_eof_offset(&signed_data)?;
    let pdf_data = &signed_data[..eof_offset];
    let suffix = &signed_data[eof_offset..];
    let signatures = extract_armored_signatures(suffix);

    if signatures.is_empty() {
        bail!("No PGP signature found after %%EOF marker");
    }

    eprintln!(
        "    Found {} signature(s)",
        style(signatures.len()).cyan()
    );

    // Load verification certificates (optional; otherwise we use the GnuPG keybox via Helper)
    let cert_source = if cert_spec.is_empty() { "keybox" } else { "cert" };
    let certs: Vec<Cert> = cert_spec
        .iter()
        .map(|spec| load_cert(spec))
        .collect::<Result<Vec<_>>>()?;

    let policy = StandardPolicy::new();
    let mut verified: Vec<VerifySignatureJson> = Vec::new();

    for sig in &signatures {
        let signer_cert: Rc<RefCell<Option<Cert>>> = Rc::new(RefCell::new(None));

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.enable_steady_tick(Duration::from_millis(80));
        spinner.set_message("Verifying signature...");

        let helper = Helper {
            certs: certs.clone(),
            keybox: None,
            signer_cert: signer_cert.clone(),
        };

        let mut verifier = DetachedVerifierBuilder::from_bytes(sig)?.with_policy(&policy, None, helper)?;

        verifier
            .verify_bytes(pdf_data)
            .context("Signature verification failed")?;

        spinner.finish_and_clear();

        let cert = signer_cert
            .borrow()
            .clone()
            .context("Signature verified but signer certificate could not be resolved")?;

        let fingerprint = cert.fingerprint().to_string();
        let uids: Vec<String> = cert
            .userids()
            .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
            .collect();

        verified.push(VerifySignatureJson {
            key_fingerprint: fingerprint,
            uids,
            cert_source: cert_source.to_string(),
        });
    }

    eprintln!(
        "\n{} {}",
        style("[VALID]").green().bold(),
        style("All signatures verified").green()
    );

    eprintln!(
        "\n    Signatures (from {}):",
        if cert_source == "cert" {
            "provided cert(s)"
        } else {
            "your GnuPG keybox"
        }
    );
    for (i, sig) in verified.iter().enumerate() {
        eprintln!(
            "      {}. Fingerprint: {}",
            i + 1,
            style(&sig.key_fingerprint).cyan()
        );
        for uid in &sig.uids {
            eprintln!("         Identity: {}", style(uid).cyan());
        }
    }

    if json {
        let first = verified.first();
        let payload = VerifyJson {
            status: "ok",
            command: "verify",
            input: input.display().to_string(),
            key_fingerprint: first
                .map(|s| s.key_fingerprint.clone())
                .unwrap_or_default(),
            uids: first.map(|s| s.uids.clone()).unwrap_or_default(),
            cert_source,
            signatures: verified,
        };
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        println!("OK");
    }

    Ok(())
}


