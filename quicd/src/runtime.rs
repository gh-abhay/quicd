use crate::config::RuntimeConfig;
use anyhow::Result;
use tokio::runtime::Runtime;

pub fn create_runtime(config: &RuntimeConfig) -> Result<Runtime> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .max_blocking_threads(config.max_blocking_threads)
        .thread_name(config.thread_name.clone())
        .thread_stack_size(config.thread_stack_size)
        .enable_all()
        .build()?;

    Ok(rt)
}
