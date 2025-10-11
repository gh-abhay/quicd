use clap::Parser;
use superd::{Superd, Config};
use std::num::NonZeroUsize;

#[derive(Parser)]
#[command(name = "superd")]
#[command(about = "High-performance QUIC daemon")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: String,

    #[arg(long, default_value = "1")]
    num_network_threads: NonZeroUsize,

    #[arg(long, default_value = "4")]
    num_processing_threads: NonZeroUsize,

    #[arg(long, default_value = "64")]
    max_batch_size: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let config = Config {
        listen_addr: args.listen.parse()?,
        num_network_threads: args.num_network_threads.get(),
        num_processing_threads: args.num_processing_threads.get(),
        max_batch_size: args.max_batch_size,
    };

    let superd = Superd::new(config).await?;
    superd.run().await?;

    Ok(())
}