use anyhow::{bail, Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

pub(crate) fn load_keybox_certs() -> Result<Vec<Cert>> {
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

    bail!("No OpenPGP certificates found in your keybox. Provide a certificate file path instead.")
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

pub(crate) fn find_certs_in_keybox(certs: &[Cert], key_spec: &str) -> Vec<Cert> {
    let needle_hex = normalize_hexish(key_spec);
    let needle_lc = key_spec.trim().to_lowercase();

    certs.iter()
        .filter_map(|cert| {
            let matches_fpr = !needle_hex.is_empty()
                && normalize_hexish(&cert.fingerprint().to_string()) == needle_hex;

            let matches_kid = !needle_hex.is_empty()
                && cert
                    .keys()
                    .any(|k| normalize_hexish(&k.key().keyid().to_string()) == needle_hex);

            let matches_uid = !needle_lc.is_empty()
                && cert.userids().any(|uid| {
                    String::from_utf8_lossy(uid.userid().value())
                        .to_lowercase()
                        .contains(&needle_lc)
                });

            if matches_fpr || matches_kid || matches_uid {
                Some(cert.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Load an OpenPGP certificate from a file path, or look it up in the GnuPG keybox.
pub(crate) fn load_cert(spec: &str) -> Result<Cert> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));

    let path = Path::new(spec);
    if path.exists() {
        spinner.set_message(format!(
            "Loading certificate from {}",
            style(path.display()).cyan()
        ));
        let result = Cert::from_bytes(&std::fs::read(path)?)
            .with_context(|| format!("Failed to load certificate from file: {}", path.display()));
        spinner.finish_and_clear();
        return result;
    }

    spinner.set_message(format!(
        "Searching GnuPG keybox for {}",
        style(spec).cyan()
    ));
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
            format!(
                "Multiple keys found for '{}'. Using the first one.",
                style(spec).cyan()
            )
        );
    }

    Ok(matches.into_iter().next().unwrap())
}


