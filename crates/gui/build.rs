fn main() {
    let attributes = tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "list_blocks",
            "add_block",
            "delete_block",
            "start_block",
            "get_status",
            "list_schedules",
            "add_schedule",
            "update_schedule",
            "delete_schedule",
        ]),
    );
    tauri_build::try_build(attributes).expect("tauri-build failed");
}
