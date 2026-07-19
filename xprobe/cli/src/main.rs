use clap::{CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(name = "xprobe", version, about = "Runtime host-to-GPU latency probe")]
struct Cli {}

fn main() {
    Cli::parse();
    Cli::command().print_help().expect("failed to write help");
    println!();
}
