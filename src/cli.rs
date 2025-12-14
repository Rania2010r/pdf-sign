use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pdf-sign",
    about = "Secure PDF signing with OpenPGP",
    long_about = "Sign and verify PDFs using OpenPGP.\nAll signing operations are delegated to gpg-agent for maximum security."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output machine-readable JSON to stdout
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
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
