use crate::json::SignJson;
use crate::keybox::load_cert;
use crate::pdf::{extract_armored_signatures, find_eof_offset};
use crate::util::format_bytes;
use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use openpgp::armor;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::SignatureType;
use sequoia_openpgp as openpgp;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn default_signed_output_path(input: &Path) -> Result<PathBuf> {
    let mut p = input.to_path_buf();
    let stem = p
        .file_stem()
        .context("Input path must include a file name (cannot derive default output path)")?;
    let mut name: OsString = stem.to_os_string();
    name.push("_signed.pdf");
    p.set_file_name(name);
    Ok(p)
}

pub(crate) fn sign_pdf(
    input: PathBuf,
    output: Option<PathBuf>,
    key_spec: String,
    embed_uid: bool,
    json: bool,
) -> Result<()> {
    eprintln!("{}", style("==> Signing PDF with GPG agent").cyan().bold());

    // Read PDF with progress
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));

    spinner.set_message(format!("Reading PDF {}", style(input.display()).cyan()));
    let mut pdf_data = Vec::new();
    let mut file = BufReader::new(
        File::open(&input).with_context(|| format!("Failed to open PDF: {}", input.display()))?,
    );
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
    let uids: Vec<_> = cert
        .userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();

    eprintln!(
        "    Using key: {} ({})",
        style(&fingerprint).cyan(),
        style(uids.join(", ")).dim()
    );

    let embedded_uid: Option<String> = if embed_uid {
        let uid = cert
            .userids()
            .next()
            .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string());
        if uid.is_none() {
            eprintln!(
                "{} {}",
                style("Warning:").yellow().bold(),
                style("No UID found to embed.").dim()
            );
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
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message("Connecting to GPG agent...");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use sequoia_gpg_agent as agent;

        // Connect to GPG agent
        let ctx = agent::Context::new().context("Failed to create GPG agent context")?;
        let agent = agent::Agent::connect(&ctx)
            .await
            .context("Failed to connect to GPG agent - is gpg-agent running?")?;

        spinner.set_message(format!(
            "{}Waiting for signing authorization (PIN/touch/passphrase may be required)...",
            style("→").cyan()
        ));

        // Get keypair that delegates to agent (may trigger PIN/touch prompt)
        let keypair = agent
            .keypair(&valid_key)
            .context("Failed to get keypair from agent - is the key available?")?;

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

        let mut signer = Signer::with_template(message, keypair, builder)?
            .detached()
            .build()?;
        signer.write_all(clean_pdf)?;
        signer.finalize()?;
        armor_writer.finalize()?;

        Ok::<(), anyhow::Error>(())
    })?;

    spinner.finish_with_message(format!(
        "[OK] Created signature ({})",
        style(format_bytes(signature_data.len())).cyan()
    ));

    // Write signed PDF
    let output_path = match output {
        Some(p) => p,
        None => default_signed_output_path(&input)?,
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!(
        "Writing signed PDF to {}",
        style(output_path.display()).cyan()
    ));

    let mut out = BufWriter::new(
        File::create(&output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path.display()))?,
    );
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

    eprintln!(
        "\n{} {}",
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
        println!("{}", output_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::default_signed_output_path;
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    #[test]
    fn default_output_path_normal() {
        let input = PathBuf::from("/tmp/document.pdf");
        let out = default_signed_output_path(&input).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/document_signed.pdf"));
    }

    #[test]
    fn default_output_path_hidden_dotfile_like_pdf() {
        let input = PathBuf::from("/tmp/.pdf");
        let out = default_signed_output_path(&input).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/.pdf_signed.pdf"));
    }

    #[test]
    fn default_output_path_root_has_no_filename() {
        let input = PathBuf::from("/");
        let err = default_signed_output_path(&input).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot derive default output path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn default_output_path_non_utf8_stem_does_not_panic() {
        let input = PathBuf::from(std::ffi::OsString::from_vec(vec![
            0xFF, 0xFE, b'.', b'p', b'd', b'f',
        ]));
        let out = default_signed_output_path(&input).unwrap();
        let name = out.file_name().unwrap();
        // We can't compare to &str here; just ensure it's the stem + suffix.
        // file_stem() strips the ".pdf" extension, so the stem is just [0xFF, 0xFE].
        let mut expected = OsStr::from_bytes(&[0xFF, 0xFE]).to_os_string();
        expected.push("_signed.pdf");
        assert_eq!(name, expected);
    }
}
