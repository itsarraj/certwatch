use std::fs;
use std::time::SystemTime;

use certwatch::expiry::{days_until, status, Status};
use certwatch::{certinfo, parse_target, tls};
use clap::Parser;

#[derive(Parser)]
#[command(name = "certwatch", about = "A TLS certificate expiry watcher")]
struct Cli {
    /// Domains to check, e.g. `example.com` or `example.com:8443`.
    targets: Vec<String>,

    /// Read targets from a file, one per line, instead of/in addition to args.
    #[arg(long)]
    file: Option<std::path::PathBuf>,

    /// Exit non-zero (and print a warning) if a cert expires within this many days.
    #[arg(long, default_value_t = 30)]
    warn_days: i64,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut targets = cli.targets;
    if let Some(path) = &cli.file {
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        targets.extend(
            content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }

    if targets.is_empty() {
        anyhow::bail!("no targets given — pass hostnames or --file domains.txt");
    }

    let mut any_problem = false;

    for target in &targets {
        let (host, port) = parse_target(target);
        match check_one(&host, port, cli.warn_days) {
            Ok((st, days, subject)) => {
                let marker = match st {
                    Status::Ok => "OK     ",
                    Status::Warning => "WARNING",
                    Status::Expired => "EXPIRED",
                };
                println!("{marker}  {host}:{port}  {days} day(s)  {subject}");
                if st != Status::Ok {
                    any_problem = true;
                }
            }
            Err(e) => {
                println!("ERROR    {host}:{port}  {e}");
                any_problem = true;
            }
        }
    }

    if any_problem {
        std::process::exit(1);
    }
    Ok(())
}

fn check_one(host: &str, port: u16, warn_days: i64) -> anyhow::Result<(Status, i64, String)> {
    let der = tls::fetch_leaf_cert_der(host, port)?;
    let info = certinfo::parse_cert(&der)?;
    let days = days_until(info.not_after, SystemTime::now());
    let st = status(days, warn_days);
    Ok((st, days, info.subject))
}
