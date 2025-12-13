#!/usr/bin/env nix-shell
//! ```cargo
//! [dependencies]
//! sequoia-openpgp = { version = "2", default-features = false, features = ["crypto-nettle"] }
//! sequoia-gpg-agent = "0.6"
//! tokio = { version = "1", features = ["full"] }
//! anyhow = "1.0"
//! clap = { version = "4.5", features = ["derive"] }
//! indicatif = "0.17"
//! console = "0.15"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```
/*
#!nix-shell -i rust-script -p rustc -p rust-script -p cargo -p pkg-config -p nettle -p gmp -p gnupg
*/

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::types::SignatureType;
use openpgp::serialize::stream::*;
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "pdf-sign",
    about = "Secure PDF signing with GPG/YubiKey",
    long_about = "Sign and verify PDFs using GPG agent with hardware token support (YubiKey, smartcards).\nAll signing operations are delegated to gpg-agent for maximum security."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output machine-readable JSON to stdout
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a PDF file using GPG agent
    Sign {
        /// Path to the PDF file to sign
        input: PathBuf,
        
        /// Output path for signed PDF (default: <input>_signed.pdf)
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Key specification: file path (.asc), fingerprint, key ID, or email
        #[arg(short, long)]
        key: String,

        /// Embed signer UID into the OpenPGP signature (adds identity metadata)
        #[arg(long)]
        embed_uid: bool,
    },
    /// Verify a signed PDF file
    Verify {
        /// Path to the signed PDF file
        input: PathBuf,
        
        /// Optional certificate/key spec. Can be provided multiple times.
        /// If omitted, verification uses your GnuPG keybox (pubring.kbx).
        #[arg(short, long)]
        cert: Vec<String>,
    },
}

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
            self.keybox = Some(load_keybox_certs()?);
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
                            // Capture the signer's certificate for later display.
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

fn find_eof_offset(data: &[u8]) -> Result<usize> {
    data.windows(5)
        .rposition(|w| w == b"%%EOF")
        .map(|pos| pos + 5)
        .context("PDF does not contain %%EOF marker")
}

const PGP_SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
const PGP_SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| start + pos)
}

/// Extract all ASCII-armored PGP signature blocks from `data` (in order).
fn extract_armored_signatures(data: &[u8]) -> Vec<Vec<u8>> {
    let mut sigs = Vec::new();
    let mut i = 0;
    while let Some(begin) = find_subslice(data, PGP_SIG_BEGIN, i) {
        let Some(end) = find_subslice(data, PGP_SIG_END, begin) else {
            break;
        };
        let mut end_pos = end + PGP_SIG_END.len();
        // Include at most one trailing newline after the END marker if present.
        if end_pos < data.len() && data[end_pos] == b'\n' {
            end_pos += 1;
        }
        sigs.push(data[begin..end_pos].to_vec());
        i = end_pos;
    }
    sigs
}

fn gnupg_home() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("GNUPGHOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").context("HOME is not set (cannot locate ~/.gnupg)")?;
    Ok(PathBuf::from(home).join(".gnupg"))
}

fn keybox_path() -> Result<PathBuf> {
    Ok(gnupg_home()?.join("pubring.kbx"))
}

fn load_keybox_certs() -> Result<Vec<Cert>> {
    use sequoia_gpg_agent::sequoia_ipc::keybox::{Keybox, KeyboxRecord};

    let primary = keybox_path()?;
    let fallback = primary.with_file_name(format!(
        "{}~",
        primary
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("pubring.kbx")
    ));

    let candidates = [primary, fallback];
    for path in candidates {
        if !path.exists() {
            continue;
        }

        let kbx = Keybox::from_file(&path)
            .with_context(|| format!("Failed to read GnuPG keybox at {}", path.display()))?;
        let certs = kbx
            .filter_map(|r| r.ok())
            .filter_map(|r| match r {
                KeyboxRecord::OpenPGP(o) => Some(o.cert()),
                _ => None,
            })
            .collect::<openpgp::Result<Vec<Cert>>>()?;

        if !certs.is_empty() {
            return Ok(certs);
        }
    }

    bail!(
        "No OpenPGP certificates found in your keybox. Provide a certificate file path instead."
    )
}

fn normalize_hexish(s: &str) -> String {
    s.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

fn find_certs_in_keybox(certs: &[Cert], key_spec: &str) -> Vec<Cert> {
    let needle_hex = normalize_hexish(key_spec);
    let needle_lc = key_spec.trim().to_lowercase();

    certs.iter().filter_map(|cert| {
        let matches_fpr = !needle_hex.is_empty()
            && normalize_hexish(&cert.fingerprint().to_string()) == needle_hex;

        let matches_kid = !needle_hex.is_empty() && cert.keys().any(|k| {
            normalize_hexish(&k.key().keyid().to_string()) == needle_hex
        });

        let matches_uid = !needle_lc.is_empty() && cert.userids().any(|uid| {
            String::from_utf8_lossy(uid.userid().value())
                .to_lowercase()
                .contains(&needle_lc)
        });

        if matches_fpr || matches_kid || matches_uid {
            Some(cert.clone())
        } else {
            None
        }
    }).collect()
}

/// Load an OpenPGP certificate from a file path, or look it up in the GnuPG keybox.
fn load_cert(spec: &str) -> Result<Cert> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));

    let path = Path::new(spec);
    if path.exists() {
        spinner.set_message(format!("Loading certificate from {}", style(path.display()).cyan()));
        let result = Cert::from_bytes(&std::fs::read(path)?)
            .context(format!("Failed to load certificate from file: {}", path.display()));
        spinner.finish_and_clear();
        return result;
    }

    spinner.set_message(format!("Searching GnuPG keybox for {}", style(spec).cyan()));
    let certs = load_keybox_certs()?;
    let matches = find_certs_in_keybox(&certs, spec);
    spinner.finish_and_clear();

    if matches.is_empty() {
        bail!(
            "No matching certificate found for '{}'. Provide a .asc file path or import the key into your keybox.",
            spec
        );
    }

    if matches.len() > 1 {
        eprintln!(
            "{} {}",
            style("Warning:").yellow().bold(),
            format!("Multiple keys found for '{}'. Using the first one.", style(spec).cyan())
        );
    }

    Ok(matches.into_iter().next().unwrap())
}

fn format_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if (bytes as f64) < MB {
        format!("{:.1} KB", bytes as f64 / KB)
    } else {
        format!("{:.2} MB", bytes as f64 / MB)
    }
}

#[derive(Serialize)]
struct SignJson<'a> {
    status: &'a str,
    command: &'a str,
    input: String,
    output: String,
    key_fingerprint: String,
    uids: Vec<String>,
    embed_uid: bool,
}

#[derive(Serialize)]
struct VerifyJson<'a> {
    status: &'a str,
    command: &'a str,
    input: String,
    key_fingerprint: String,
    uids: Vec<String>,
    cert_source: &'a str,
    signatures: Vec<VerifySignatureJson>,
}

#[derive(Serialize)]
struct VerifySignatureJson {
    key_fingerprint: String,
    uids: Vec<String>,
    cert_source: String,
}

#[derive(Serialize)]
struct ErrorJson<'a> {
    status: &'a str,
    error: String,
    causes: Vec<String>,
}

fn sign_pdf(input: PathBuf, output: Option<PathBuf>, key_spec: String, embed_uid: bool, json: bool) -> Result<()> {
    eprintln!("{}", 
        style("==> Signing PDF with GPG agent").cyan().bold()
    );
    
    // Read PDF with progress
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    
    spinner.set_message(format!("Reading PDF {}", style(input.display()).cyan()));
    let mut pdf_data = Vec::new();
    let mut file = BufReader::new(File::open(&input)
        .context(format!("Failed to open PDF: {}", input.display()))?);
    file.read_to_end(&mut pdf_data)?;
    spinner.finish_with_message(format!(
        "[OK] Read PDF ({})",
        style(format_bytes(pdf_data.len())).cyan()
    ));

    let eof_offset = find_eof_offset(&pdf_data)?;
    let clean_pdf = &pdf_data[..eof_offset];
    let existing_suffix = &pdf_data[eof_offset..];
    let existing_sigs = extract_armored_signatures(existing_suffix);

    // Load certificate
    let cert = load_cert(&key_spec)?;
    
    // Display key info
    let fingerprint = cert.fingerprint();
    let uids: Vec<_> = cert.userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();
    
    eprintln!("    Using key: {} ({})",
        style(&fingerprint).cyan(),
        style(uids.join(", ")).dim()
    );

    let embedded_uid: Option<String> = if embed_uid {
        let uid = cert.userids()
            .next()
            .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string());
        if uid.is_none() {
            eprintln!("{} {}", style("Warning:").yellow().bold(), style("No UID found to embed.").dim());
        }
        uid
    } else {
        None
    };
    
    let policy = StandardPolicy::new();

    // Find signing-capable key
    let valid_key = cert
        .keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .context("No valid signing key found in certificate")?
        .key()
        .clone();

    // Create detached signature using GPG agent
    let mut signature_data = Vec::new();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message("Connecting to GPG agent...");
    
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use sequoia_gpg_agent as agent;
        
        // Connect to GPG agent
        let ctx = agent::Context::new()
            .context("Failed to create GPG agent context")?;
        let agent = agent::Agent::connect(&ctx).await
            .context("Failed to connect to GPG agent - is gpg-agent running?")?;
        
        spinner.set_message(format!(
            "{}Waiting for hardware token (PIN/touch may be required)...",
            style("→").cyan()
        ));
        
        // Get keypair that delegates to agent (triggers PIN/touch prompt)
        let keypair = agent.keypair(&valid_key)
            .context("Failed to get keypair from agent - is the key available on your token?")?;

        spinner.set_message("Creating signature...");
        
        // Create armored detached signature
        let mut armor_writer = armor::Writer::new(&mut signature_data, armor::Kind::Signature)?;
        let message = Message::new(&mut armor_writer);

        let mut builder = SignatureBuilder::new(SignatureType::Binary);
        if let Some(uid) = &embedded_uid {
            builder = builder.add_notation(
                "pdf-sign.uid",
                uid.as_bytes(),
                NotationDataFlags::empty().set_human_readable(),
                false,
            )?;
        }

        let mut signer = Signer::with_template(message, keypair, builder)?.detached().build()?;
        signer.write_all(clean_pdf)?;
        signer.finalize()?;
        armor_writer.finalize()?;
        
        Ok::<(), anyhow::Error>(())
    })?;
    
    spinner.finish_with_message(format!("[OK] Created signature ({})", style(format_bytes(signature_data.len())).cyan()));

    // Write signed PDF
    let output_path = output.unwrap_or_else(|| {
        let mut p = input.clone();
        let stem = p.file_stem().unwrap().to_str().unwrap();
        p.set_file_name(format!("{}_signed.pdf", stem));
        p
    });

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!("Writing signed PDF to {}", style(output_path.display()).cyan()));

    let mut out = BufWriter::new(File::create(&output_path)
        .context(format!("Failed to create output file: {}", output_path.display()))?);
    out.write_all(clean_pdf)?;
    out.write_all(b"\n")?;
    // Preserve any existing appended signatures, then append the new signature.
    for sig in &existing_sigs {
        out.write_all(sig)?;
        if !sig.ends_with(b"\n") {
            out.write_all(b"\n")?;
        }
    }
    out.write_all(&signature_data)?;
    out.flush()?;
    
    spinner.finish_and_clear();

    eprintln!("\n{} {}",
        style("[SUCCESS]").green().bold(),
        style("Signed successfully").cyan()
    );
    
    if json {
        let payload = SignJson {
            status: "ok",
            command: "sign",
            input: input.display().to_string(),
            output: output_path.display().to_string(),
            key_fingerprint: fingerprint.to_string(),
            uids,
            embed_uid,
        };
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        // Output the path to stdout for shell piping/scripting
        println!("{}", output_path.display());
    }
    
    Ok(())
}

fn verify_pdf(input: PathBuf, cert_spec: Vec<String>, json: bool) -> Result<()> {
    eprintln!("{}",
        style("==> Verifying PDF signature").cyan().bold()
    );
    
    // Read signed PDF
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!("Reading signed PDF {}", style(input.display()).cyan()));
    
    let mut signed_data = Vec::new();
    let mut file = BufReader::new(File::open(&input)
        .context(format!("Failed to open signed PDF: {}", input.display()))?);
    file.read_to_end(&mut signed_data)?;
    
    spinner.finish_with_message(format!("[OK] Read PDF ({})", style(format_bytes(signed_data.len())).cyan()));

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

    // Load verification certificates (optional; otherwise we use the GnuPG keybox)
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
                .unwrap()
        );
        spinner.enable_steady_tick(Duration::from_millis(80));
        spinner.set_message("Verifying signature...");

        let helper = Helper { certs: certs.clone(), keybox: None, signer_cert: signer_cert.clone() };

        let mut verifier = DetachedVerifierBuilder::from_bytes(sig)?
            .with_policy(&policy, None, helper)?;

        verifier.verify_bytes(pdf_data)
            .context("Signature verification failed")?;

        spinner.finish_and_clear();

        let cert = signer_cert
            .borrow()
            .clone()
            .context("Signature verified but signer certificate could not be resolved")?;

        let fingerprint = cert.fingerprint().to_string();
        let uids: Vec<String> = cert.userids()
            .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
            .collect();

        verified.push(VerifySignatureJson {
            key_fingerprint: fingerprint,
            uids,
            cert_source: cert_source.to_string(),
        });
    }

    // Display verification results to stderr
    eprintln!("\n{} {}",
        style("[VALID]").green().bold(),
        style("All signatures verified").green()
    );

    eprintln!(
        "\n    Signatures (from {}):",
        if cert_source == "cert" { "provided cert(s)" } else { "your GnuPG keybox" }
    );
    for (i, sig) in verified.iter().enumerate() {
        eprintln!("      {}. Fingerprint: {}", i + 1, style(&sig.key_fingerprint).cyan());
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
            key_fingerprint: first.map(|s| s.key_fingerprint.clone()).unwrap_or_default(),
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.json;

    let result = match cli.command {
        Commands::Sign { input, output, key, embed_uid } => sign_pdf(input, output, key, embed_uid, json),
        Commands::Verify { input, cert } => verify_pdf(input, cert, json),
    };

    if let Err(e) = &result {
        if json {
            let causes: Vec<String> = e.chain().skip(1).map(|c| c.to_string()).collect();
            let payload = ErrorJson {
                status: "error",
                error: e.to_string(),
                causes,
            };
            // JSON goes to stdout for tooling.
            println!("{}", serde_json::to_string(&payload)?);
        } else {
            eprintln!("\n{} {}", 
                style("[ERROR]").red().bold(),
                style(&e).red()
            );
            
            for (i, cause) in e.chain().skip(1).enumerate() {
                if i == 0 {
                    eprintln!("\n    Caused by:");
                }
                eprintln!("      - {}", style(cause).red());
            }
            eprintln!();
        }
    }

    result
}
