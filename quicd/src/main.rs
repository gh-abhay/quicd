mod config;
mod runtime;

fn main() -> anyhow::Result<()> {
    let config = config::load_config()?;

    println!("Loaded config: {:?}", config);

    // Initialize the Tokio runtime
    let rt = runtime::create_runtime(&config.runtime)?;

    // Run the server on the runtime
    rt.block_on(async {
        println!("QuickD server starting on {}:{}", config.host, config.port);
        // TODO: Start server logic here
        Ok(())
    })
}