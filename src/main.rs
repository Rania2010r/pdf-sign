use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = pdf_sign::cli::Cli::parse();
    match pdf_sign::app::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
