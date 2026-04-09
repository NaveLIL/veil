use std::io::Result;

fn main() -> Result<()> {
    let proto_files = [
        "../veil-proto/veil/v1/envelope.proto",
        "../veil-proto/veil/v1/auth.proto",
        "../veil-proto/veil/v1/chat.proto",
        "../veil-proto/veil/v1/presence.proto",
        "../veil-proto/veil/v1/share.proto",
        "../veil-proto/veil/v1/media.proto",
        "../veil-proto/veil/v1/voice.proto",
        "../veil-proto/veil/v1/server.proto",
    ];

    prost_build::compile_protos(&proto_files, &["../veil-proto"])?;

    // Rebuild if any .proto file changes
    for f in &proto_files {
        println!("cargo:rerun-if-changed={f}");
    }

    Ok(())
}
