// vynm entry point: parse, run, map errors onto the exit-code contract.
use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = vynkor_manager::cli::Cli::parse();
    if let Err(e) = vynkor_manager::cli::run(&cli).await {
        eprintln!("error: {e}");
        std::process::exit(vynkor_manager::cli::exit_code(&e));
    }
}
