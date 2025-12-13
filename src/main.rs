use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = pdf_sign::cli::Cli::parse();
    pdf_sign::app::run(cli)
}


