fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/icons/SSLRay.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest.join("../../assets/icons/SSLRay.ico");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let resource = output.join("sslray-icon.rc");
    // Resource compilers accept forward slashes on Windows. Quote embedded paths
    // for workspaces containing spaces; the artwork never controls RC syntax.
    assert!(
        icon.is_file(),
        "SSLRay.ico is missing; run scripts/generate-icons.py"
    );
    let icon = icon
        .to_str()
        .expect("Windows resource paths must be valid Unicode")
        .replace('\\', "/")
        .replace('"', "\\\"");
    std::fs::write(
        &resource,
        format!("#pragma code_page(65001)\n1 ICON \"{icon}\"\n"),
    )
    .expect("Cannot write the Windows icon resource");

    // Fail a Windows build when the resource compiler is missing instead of
    // silently delivering an executable with the generic application icon.
    // No UAC manifest is added: the desktop process stays unelevated.
    embed_resource::compile_for(&resource, ["sslray"], embed_resource::NONE)
        .manifest_required()
        .expect("Cannot embed SSLRay's Windows icon resource");
}
