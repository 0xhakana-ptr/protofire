use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Build,
    Run,
    Test,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build => { /* ... */ }
        Commands::Run => { /* ... */ }
        Commands::Test => { /* ... */ }
    }
    Ok(())
}