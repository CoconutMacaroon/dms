use serde::Deserialize;
use std::fs::read_to_string;
/// A server configuration:
/// * `upload_path` Location to store uploaded files. A trailing `/` will be
/// added if not already present.
/// * `workers` Number of workers for the web server to use
/// * `listen_addr` Address to listen for incoming requests
/// * `listen_port` Port to listen on
#[derive(Deserialize)]
pub struct Configuration {
    pub upload_path: String,
    pub workers: usize,
    pub listen_addr: String,
    pub listen_port: u16,
}

/// Returns a `Configuration` loaded from `config.toml`
pub fn get_config() -> Configuration {
    let raw_config = read_to_string("config.toml").unwrap();
    let mut processed_config: Configuration = toml::from_str(&raw_config).expect("msg");
    if !(processed_config.upload_path.ends_with('/')
        || processed_config.upload_path.ends_with('\\'))
    {
        processed_config.upload_path.push('/');
    }
    processed_config
}
