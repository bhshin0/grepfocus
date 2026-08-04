fn main() {
    let attributes =
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "list_blocks",
            "add_block",
            "update_block",
            "delete_block",
            "start_block",
            "get_status",
            "get_usage_stats",
            "list_schedules",
            "add_schedule",
            "update_schedule",
            "delete_schedule",
            "set_password",
            "set_license",
            "set_settings",
            "unlock",
            "take_break",
            "get_break_challenge",
            "start_pomodoro",
            "stop_pomodoro",
            "app_env",
            "install_service",
            "uninstall_service",
        ]));
    tauri_build::try_build(attributes).expect("tauri-build failed");
}
