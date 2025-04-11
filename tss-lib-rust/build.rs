use std::{io::Result, path::Path};

fn main() -> Result<()> {
    let proto_dir = "proto";
    let out_dir = "src/protob";

    println!("cargo:rerun-if-changed={}", proto_dir); // Rerun build script if proto files change

    // Ensure the output directory exists
    std::fs::create_dir_all(out_dir)?;

    // Find all .proto files in the proto directory
    let proto_files: Vec<_> = std::fs::read_dir(proto_dir)?
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_file() && path.extension() == Some("proto".as_ref()) {
                    Some(path)
                } else {
                    None
                }
            })
        })
        .collect();

    if proto_files.is_empty() {
        eprintln!("Warning: No .proto files found in {}", proto_dir);
        return Ok(());
    }

    // Convert pathbufs to string slices for prost_build
    let proto_file_paths: Vec<&str> = proto_files
        .iter()
        .map(|p| p.to_str().expect("Proto path is not valid UTF-8"))
        .collect();

    prost_build::Config::new()
        .out_dir(out_dir) // Output generated Rust files here
        .compile_protos(&proto_file_paths, // Input proto files
                        &[proto_dir])?; // Include path for imports

    Ok(())
} 