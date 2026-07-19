use std::{error::Error, fs, path::PathBuf};

use xprobe_protocol::schema::generated_schemas;

fn main() -> Result<(), Box<dyn Error>> {
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
    fs::create_dir_all(&output_dir)?;

    for (file_name, schema) in generated_schemas() {
        let json = serde_json::to_string_pretty(&schema)?;
        fs::write(output_dir.join(file_name), format!("{json}\n"))?;
    }

    Ok(())
}
