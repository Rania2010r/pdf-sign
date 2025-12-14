use crate::cli::{Cli, Commands};
use crate::json::ErrorJson;
use crate::sign::sign_pdf;
use crate::verify::verify_pdf;
use anyhow::Result;
use console::style;

pub fn run(cli: Cli) -> Result<()> {
    let json = cli.json;

    let result = match cli.command {
        Commands::Sign {
            input,
            output,
            key,
            embed_uid,
        } => sign_pdf(input, output, key, embed_uid, json),
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
            eprintln!("\n{} {}", style("[ERROR]").red().bold(), style(&e).red());

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
