use ckb_idl_cli::cli::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = ckb_idl_cli::cli::run(cli) {
        eprintln!("{error}");
        std::process::exit(error.exit_code());
    }
}
