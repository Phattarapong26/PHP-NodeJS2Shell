//! Tauri desktop shell for ThaiCERT Scanner.
//!
//! The UI is a normal Svelte single page app; the backend stays a separate
//! service that the webview talks to over HTTP (see `src/lib/core/api.ts`).

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running ThaiCERT Scanner");
}
