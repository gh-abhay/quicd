use clap::Parser;
use superd::{Superd, Config};

#[derive(Parser)]
#[command(name = "superd")]
#[command(about = "High-performance QUIC daemon")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let config = Config {
        listen_addr: args.listen.parse()?,
    };

    let superd = Superd::new(config).await?;
    superd.run().await?;

    Ok(())
}