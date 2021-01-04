use std::env;
use std::path::Path;

use anyhow::Error;

fn main() -> Result<(), Error> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_dir = Path::new(&crate_dir);

    if cfg!(feature = "capi") {
        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(cbindgen::Config::from_root_or_default(&crate_dir))
            .generate()?
            .write_to_file(crate_dir.join("include/hassh.h"));
    }

    Ok(())
}
