use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use base64::Engine;
use image::codecs::jpeg::JpegEncoder;
use image::{GenericImageView, ImageFormat, Limits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};

use super::AppState;

const SETTINGS_VERSION: u8 = 1;
const SETTINGS_FILE: &str = "settings-v1.json";
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;
const MAX_SOURCE_BYTES: u64 = 12 * 1024 * 1024;
const MAX_SOURCE_DIMENSION: u32 = 8_192;
const MAX_SOURCE_PIXELS: u64 = 32_000_000;
const MAX_STORED_DIMENSION: u32 = 4_096;
const MAX_STORED_BYTES: usize = 12 * 1024 * 1024;
const JPEG_QUALITY: u8 = 88;
const MAX_DECODE_ALLOC_BYTES: u64 = 192 * 1024 * 1024;

static APPEARANCE_IO: Mutex<()> = Mutex::new(());
static APPEARANCE_MUTATION_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

const THEMES: &[&str] = &["veil", "midnight", "ocean", "forest", "oled"];
const UI_SCALES: &[u8] = &[90, 100, 110, 125];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct AppearanceSettings {
    pub version: u8,
    pub theme_id: String,
    pub wallpaper_asset_id: Option<String>,
    pub wallpaper_dim: u8,
    pub wallpaper_blur: u8,
    pub wallpaper_position_x: u8,
    pub wallpaper_position_y: u8,
    pub show_on_lock_screen: bool,
    pub reduce_motion: bool,
    pub ui_scale: u8,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            theme_id: "veil".to_string(),
            wallpaper_asset_id: None,
            wallpaper_dim: 52,
            wallpaper_blur: 0,
            wallpaper_position_x: 50,
            wallpaper_position_y: 50,
            show_on_lock_screen: false,
            reduce_motion: false,
            ui_scale: 100,
        }
    }
}

impl AppearanceSettings {
    fn validated(mut self) -> Self {
        self.version = SETTINGS_VERSION;
        if !THEMES.contains(&self.theme_id.as_str()) {
            self.theme_id = "veil".to_string();
        }
        if self
            .wallpaper_asset_id
            .as_deref()
            .is_some_and(|id| !valid_asset_id(id))
        {
            self.wallpaper_asset_id = None;
        }
        self.wallpaper_dim = self.wallpaper_dim.clamp(20, 85);
        self.wallpaper_blur = self.wallpaper_blur.min(24);
        self.wallpaper_position_x = self.wallpaper_position_x.min(100);
        self.wallpaper_position_y = self.wallpaper_position_y.min(100);
        if !UI_SCALES.contains(&self.ui_scale) {
            self.ui_scale = 100;
        }
        self
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WallpaperPayload {
    asset_id: String,
    mime_type: &'static str,
    data_base64: String,
    width: u32,
    height: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WallpaperSelection {
    settings: AppearanceSettings,
    wallpaper: WallpaperPayload,
}

struct AppearanceMutationGuard;

impl Drop for AppearanceMutationGuard {
    fn drop(&mut self) {
        APPEARANCE_MUTATION_IN_PROGRESS.store(false, Ordering::Release);
    }
}

fn begin_mutation() -> Result<AppearanceMutationGuard, String> {
    APPEARANCE_MUTATION_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "another appearance update is already in progress".to_string())?;
    Ok(AppearanceMutationGuard)
}

fn lock_appearance_io() -> Result<MutexGuard<'static, ()>, String> {
    APPEARANCE_IO
        .lock()
        .map_err(|_| "appearance storage lock is poisoned".to_string())
}

fn appearance_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("appearance app-data path: {e}"))?;
    fs::create_dir_all(&app_data).map_err(|e| format!("create app-data directory: {e}"))?;
    let app_data =
        fs::canonicalize(&app_data).map_err(|e| format!("canonicalize app-data directory: {e}"))?;
    let dir = app_data.join("appearance");
    if let Ok(metadata) = fs::symlink_metadata(&dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("appearance path is not a trusted directory".to_string());
        }
    }
    fs::create_dir_all(&dir).map_err(|e| format!("create appearance directory: {e}"))?;
    let canonical =
        fs::canonicalize(&dir).map_err(|e| format!("canonicalize appearance directory: {e}"))?;
    if !canonical.starts_with(&app_data) {
        return Err("appearance directory escapes app-data".to_string());
    }
    Ok(canonical)
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(appearance_dir(app)?.join(SETTINGS_FILE))
}

fn valid_asset_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn asset_id_for_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..16])
}

fn wallpaper_path(app: &AppHandle, asset_id: &str) -> Result<PathBuf, String> {
    if !valid_asset_id(asset_id) {
        return Err("invalid wallpaper asset id".to_string());
    }
    Ok(appearance_dir(app)?.join(format!("wallpaper-{asset_id}.jpg")))
}

fn read_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Err(format!("read {label} metadata: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!("{label} has an invalid size"));
    }
    let mut file = fs::File::open(path).map_err(|e| format!("open {label}: {e}"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {label}: {e}"))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

fn read_settings(app: &AppHandle) -> Result<AppearanceSettings, String> {
    let path = settings_path(app)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(AppearanceSettings::default())
        }
        Err(error) => Err(format!("read appearance settings metadata: {error}")),
        Ok(_) => {
            let bytes = read_regular_file(&path, MAX_SETTINGS_BYTES, "appearance settings")?;
            serde_json::from_slice::<AppearanceSettings>(&bytes)
                .map(AppearanceSettings::validated)
                .map_err(|e| format!("parse appearance settings: {e}"))
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "appearance file has no parent directory".to_string())?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("refusing to replace a non-regular appearance file".to_string());
        }
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".veil-appearance-")
        .tempfile_in(parent)
        .map_err(|e| format!("create unique appearance temp file: {e}"))?;
    temporary
        .write_all(bytes)
        .map_err(|e| format!("write appearance temp file: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("sync appearance temp file: {e}"))?;
    temporary
        .persist(path)
        .map_err(|e| format!("atomically replace appearance file: {}", e.error))?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn remove_all_wallpapers(app: &AppHandle) -> Result<(), String> {
    let dir = appearance_dir(app)?;
    for entry in fs::read_dir(dir).map_err(|e| format!("scan appearance assets: {e}"))? {
        let entry = entry.map_err(|e| format!("read appearance asset: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("wallpaper-") && name.ends_with(".jpg") {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|e| format!("inspect wallpaper asset before removal: {e}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("refusing to remove a non-regular wallpaper asset".to_string());
            }
            fs::remove_file(entry.path())
                .map_err(|e| format!("remove obsolete wallpaper asset: {e}"))?;
        }
    }
    Ok(())
}

fn cleanup_orphaned_files(app: &AppHandle, active_asset_id: Option<&str>) -> Result<(), String> {
    let dir = appearance_dir(app)?;
    for entry in fs::read_dir(dir).map_err(|e| format!("scan appearance files: {e}"))? {
        let entry = entry.map_err(|e| format!("read appearance file: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let orphaned_wallpaper = name
            .strip_prefix("wallpaper-")
            .and_then(|value| value.strip_suffix(".jpg"))
            .is_some_and(|asset_id| valid_asset_id(asset_id) && Some(asset_id) != active_asset_id);
        let abandoned_temp = name.starts_with(".veil-appearance-");
        if !orphaned_wallpaper && !abandoned_temp {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|e| format!("inspect orphaned appearance file: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        fs::remove_file(entry.path())
            .map_err(|e| format!("remove orphaned appearance file: {e}"))?;
    }
    Ok(())
}

fn require_active_session(state: &State<'_, AppState>) -> Result<(), String> {
    super::require_unlocked(state)
        .map_err(|reason| format!("appearance changes require an unlocked session: {reason}"))
}

fn require_session_still_active(state: &State<'_, AppState>) -> Result<(), String> {
    if !state.unlocked.load(Ordering::Acquire) {
        return Err("application locked while updating appearance".to_string());
    }
    Ok(())
}

fn capture_active_session_epoch(state: &State<'_, AppState>) -> Result<u64, String> {
    require_active_session(state)?;
    let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_session_still_active(state)?;
    Ok(state.session_epoch.load(Ordering::Acquire))
}

fn decoder_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIMENSION);
    limits.max_image_height = Some(MAX_SOURCE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);
    limits
}

fn validate_source_dimensions(width: u32, height: u32) -> Result<(), String> {
    let pixels = u64::from(width) * u64::from(height);
    if width < 64
        || height < 64
        || width > MAX_SOURCE_DIMENSION
        || height > MAX_SOURCE_DIMENSION
        || pixels > MAX_SOURCE_PIXELS
    {
        return Err(
            "wallpaper dimensions must be at least 64x64 and at most 8192x8192 / 32 MP".to_string(),
        );
    }
    Ok(())
}

fn encode_wallpaper(path: &Path) -> Result<(Vec<u8>, u32, u32), String> {
    // Read one bounded snapshot. Dimension probing and decoding must consume
    // the same bytes so a concurrently replaced source cannot bypass limits.
    let source = read_regular_file(path, MAX_SOURCE_BYTES, "selected wallpaper")?;
    let mut reader = image::ImageReader::new(Cursor::new(source.as_slice()))
        .with_guessed_format()
        .map_err(|e| format!("detect selected image type: {e}"))?;
    reader.limits(decoder_limits());
    let format = reader
        .format()
        .ok_or_else(|| "wallpaper type could not be detected".to_string())?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
    ) {
        return Err("wallpaper must be PNG, JPEG, or WebP".to_string());
    }

    // Read dimensions before allocating a decoded pixel buffer. File-size limits
    // alone do not stop a highly compressed image from exhausting memory.
    let (source_width, source_height) = reader
        .into_dimensions()
        .map_err(|e| format!("read selected image dimensions: {e}"))?;
    validate_source_dimensions(source_width, source_height)?;

    let mut decode_reader = image::ImageReader::new(Cursor::new(source.as_slice()))
        .with_guessed_format()
        .map_err(|e| format!("redetect selected image type: {e}"))?;
    decode_reader.limits(decoder_limits());
    let image = decode_reader
        .decode()
        .map_err(|e| format!("decode selected image: {e}"))?;

    let resized = if source_width > MAX_STORED_DIMENSION || source_height > MAX_STORED_DIMENSION {
        image.resize(
            MAX_STORED_DIMENSION,
            MAX_STORED_DIMENSION,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        image
    };
    let (width, height) = resized.dimensions();
    let mut encoded = Vec::new();
    JpegEncoder::new_with_quality(&mut encoded, JPEG_QUALITY)
        .encode_image(&resized)
        .map_err(|e| format!("sanitize selected image: {e}"))?;
    if encoded.len() > MAX_STORED_BYTES {
        return Err("sanitized wallpaper is still larger than 12 MB".to_string());
    }
    Ok((encoded, width, height))
}

fn read_verified_wallpaper(app: &AppHandle, asset_id: &str) -> Result<(Vec<u8>, u32, u32), String> {
    let bytes = read_regular_file(
        &wallpaper_path(app, asset_id)?,
        u64::try_from(MAX_STORED_BYTES).unwrap_or(u64::MAX),
        "stored wallpaper",
    )?;
    if asset_id_for_bytes(&bytes) != asset_id.to_ascii_lowercase() {
        return Err("stored wallpaper integrity check failed".to_string());
    }
    if image::guess_format(&bytes).map_err(|e| format!("detect stored wallpaper type: {e}"))?
        != ImageFormat::Jpeg
    {
        return Err("stored wallpaper is not a sanitized JPEG".to_string());
    }
    let mut reader = image::ImageReader::new(Cursor::new(bytes.as_slice()))
        .with_guessed_format()
        .map_err(|e| format!("inspect stored wallpaper: {e}"))?;
    reader.limits(decoder_limits());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|e| format!("read stored wallpaper dimensions: {e}"))?;
    if width == 0
        || height == 0
        || width > MAX_STORED_DIMENSION
        || height > MAX_STORED_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_SOURCE_PIXELS
    {
        return Err("stored wallpaper dimensions are invalid".to_string());
    }
    Ok((bytes, width, height))
}

fn payload_from_bytes(
    asset_id: String,
    bytes: Vec<u8>,
    width: u32,
    height: u32,
) -> WallpaperPayload {
    WallpaperPayload {
        asset_id,
        mime_type: "image/jpeg",
        data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        width,
        height,
    }
}

#[tauri::command]
pub(crate) fn get_appearance_settings(app: AppHandle) -> Result<AppearanceSettings, String> {
    let _io = lock_appearance_io()?;
    let settings = read_settings(&app)?;
    // Cleanup is maintenance, not part of reading a valid preference file.
    // A transient antivirus/file-lock failure must not make the whole theme
    // fail to initialize.
    let active_asset_is_valid = settings
        .wallpaper_asset_id
        .as_deref()
        .is_none_or(|asset_id| read_verified_wallpaper(&app, asset_id).is_ok());
    if active_asset_is_valid && !APPEARANCE_MUTATION_IN_PROGRESS.load(Ordering::Acquire) {
        let _ = cleanup_orphaned_files(&app, settings.wallpaper_asset_id.as_deref());
    }
    Ok(settings)
}

#[tauri::command]
pub(crate) fn save_appearance_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: AppearanceSettings,
) -> Result<AppearanceSettings, String> {
    let _mutation = begin_mutation()?;
    let expected_session_epoch = capture_active_session_epoch(&state)?;
    let settings = settings.validated();
    {
        let _io = lock_appearance_io()?;
        if let Some(asset_id) = settings.wallpaper_asset_id.as_deref() {
            read_verified_wallpaper(&app, asset_id)?;
        }
    }
    let bytes = serde_json::to_vec_pretty(&settings)
        .map_err(|e| format!("serialize appearance settings: {e}"))?;
    require_active_session(&state)?;
    let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_session_still_active(&state)?;
    if state.session_epoch.load(Ordering::Acquire) != expected_session_epoch {
        return Err("appearance settings expired after the session changed".to_string());
    }
    let _io = lock_appearance_io()?;
    atomic_write(&settings_path(&app)?, &bytes)?;
    Ok(settings)
}

#[tauri::command]
pub(crate) async fn choose_appearance_wallpaper(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: AppearanceSettings,
) -> Result<Option<WallpaperSelection>, String> {
    let _mutation = begin_mutation()?;
    require_active_session(&state)?;
    let expected_session_epoch = capture_active_session_epoch(&state)?;
    let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Choose Veil wallpaper")
        .add_filter("Images", &["png", "jpg", "jpeg", "webp"])
        .pick_file()
        .await
    else {
        return Ok(None);
    };
    let selected_path = file.path().to_path_buf();
    let (encoded, width, height) =
        tauri::async_runtime::spawn_blocking(move || encode_wallpaper(&selected_path))
            .await
            .map_err(|e| format!("wallpaper worker failed: {e}"))??;

    let asset_id = asset_id_for_bytes(&encoded);
    let asset_path = wallpaper_path(&app, &asset_id)?;
    let previous_asset_id = {
        let _io = lock_appearance_io()?;
        let previous = read_settings(&app)?;
        atomic_write(&asset_path, &encoded)?;
        previous.wallpaper_asset_id
    };

    let mut settings = settings.validated();
    settings.wallpaper_asset_id = Some(asset_id.clone());
    let settings_bytes = serde_json::to_vec_pretty(&settings)
        .map_err(|e| format!("serialize appearance settings: {e}"))?;
    let wallpaper = payload_from_bytes(asset_id.clone(), encoded, width, height);

    require_active_session(&state)?;
    let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_session_still_active(&state)?;
    if state.session_epoch.load(Ordering::Acquire) != expected_session_epoch {
        drop(_session);
        if previous_asset_id.as_deref() != Some(asset_id.as_str()) {
            let _io = lock_appearance_io()?;
            let _ = fs::remove_file(&asset_path);
        }
        return Err("wallpaper selection expired after the session changed".to_string());
    }
    let _io = lock_appearance_io()?;
    if let Err(error) = atomic_write(&settings_path(&app)?, &settings_bytes) {
        if previous_asset_id.as_deref() != Some(asset_id.as_str()) {
            let _ = fs::remove_file(&asset_path);
        }
        return Err(error);
    }

    Ok(Some(WallpaperSelection {
        settings,
        wallpaper,
    }))
}

#[tauri::command]
pub(crate) fn load_appearance_wallpaper(
    app: AppHandle,
    state: State<'_, AppState>,
    asset_id: String,
) -> Result<WallpaperPayload, String> {
    if state.unlocked.load(Ordering::Acquire) {
        // Refresh auto-lock state before deciding whether the wallpaper may cross
        // the native lock boundary. An expired session is treated as locked.
        if let Err(reason) = super::require_unlocked(&state) {
            if state.unlocked.load(Ordering::Acquire) {
                return Err(format!("refresh appearance privacy state: {reason}"));
            }
        }
    }
    let (initially_unlocked, initial_session_epoch) = {
        let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
        (
            state.unlocked.load(Ordering::Acquire),
            state.session_epoch.load(Ordering::Acquire),
        )
    };
    let (bytes, width, height) = {
        let _io = lock_appearance_io()?;
        let settings = read_settings(&app)?;
        if settings.wallpaper_asset_id.as_deref() != Some(asset_id.as_str()) {
            return Err("wallpaper asset is not active".to_string());
        }
        read_verified_wallpaper(&app, &asset_id)?
    };
    let payload = payload_from_bytes(asset_id.clone(), bytes, width, height);

    let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
    let _io = lock_appearance_io()?;
    let current = read_settings(&app)?;
    if current.wallpaper_asset_id.as_deref() != Some(asset_id.as_str()) {
        return Err("wallpaper asset changed while it was loading".to_string());
    }
    if !current.show_on_lock_screen
        && (!initially_unlocked
            || !state.unlocked.load(Ordering::Acquire)
            || state.session_epoch.load(Ordering::Acquire) != initial_session_epoch)
    {
        return Err("wallpaper is hidden after the session changed".to_string());
    }
    Ok(payload)
}

#[tauri::command]
pub(crate) fn remove_appearance_wallpaper(
    app: AppHandle,
    state: State<'_, AppState>,
    asset_id: Option<String>,
) -> Result<(), String> {
    let _mutation = begin_mutation()?;
    require_active_session(&state)?;
    let _session = state.session_transition.lock().map_err(|e| e.to_string())?;
    require_session_still_active(&state)?;
    let _io = lock_appearance_io()?;
    let settings = read_settings(&app)?;
    if let Some(asset_id) = asset_id {
        if settings.wallpaper_asset_id.as_deref() == Some(asset_id.as_str()) {
            return Err("clear the active wallpaper setting before deleting its asset".to_string());
        }
        let path = wallpaper_path(&app, &asset_id)?;
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("refusing to remove a non-regular wallpaper asset".to_string());
            }
            fs::remove_file(path).map_err(|e| format!("remove wallpaper asset: {e}"))?;
        }
        return Ok(());
    }
    if settings.wallpaper_asset_id.is_some() {
        return Err("clear the active wallpaper setting before deleting all assets".to_string());
    }
    remove_all_wallpapers(&app)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use image::{DynamicImage, ImageFormat};

    use super::{
        asset_id_for_bytes, atomic_write, encode_wallpaper, read_regular_file, valid_asset_id,
        AppearanceSettings,
    };

    fn temporary_png(width: u32, height: u32) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "veil-appearance-{}-{nonce}.png",
            std::process::id()
        ));
        DynamicImage::new_rgba8(width, height)
            .save_with_format(&path, ImageFormat::Png)
            .expect("write test image");
        path
    }

    #[test]
    fn appearance_settings_fail_closed_to_supported_ranges() {
        let settings = AppearanceSettings {
            theme_id: "remote-css".to_string(),
            wallpaper_asset_id: Some("../../secret".to_string()),
            wallpaper_dim: 0,
            wallpaper_blur: 255,
            wallpaper_position_x: 255,
            wallpaper_position_y: 255,
            ..AppearanceSettings::default()
        }
        .validated();

        assert_eq!(settings.theme_id, "veil");
        assert_eq!(settings.wallpaper_asset_id, None);
        assert_eq!(settings.wallpaper_dim, 20);
        assert_eq!(settings.wallpaper_blur, 24);
        assert_eq!(settings.wallpaper_position_x, 100);
        assert_eq!(settings.wallpaper_position_y, 100);
        assert_eq!(settings.ui_scale, 100);
    }

    #[test]
    fn asset_ids_are_fixed_length_hex_only() {
        assert!(valid_asset_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_asset_id("ABCDEF0123456789ABCDEF0123456789"));
        assert!(!valid_asset_id("0123456789abcdef0123456789abcde"));
        assert!(!valid_asset_id("../../0123456789abcdef0123456789"));
        assert_eq!(asset_id_for_bytes(b"veil").len(), 32);
        assert_ne!(asset_id_for_bytes(b"veil"), asset_id_for_bytes(b"Veil"));
    }

    #[test]
    fn appearance_files_are_replaced_and_read_with_explicit_bounds() {
        let directory = tempfile::tempdir().expect("temporary appearance directory");
        let path = directory.path().join("settings-v1.json");
        atomic_write(&path, b"first").expect("initial atomic write");
        atomic_write(&path, b"second").expect("atomic replacement");

        assert_eq!(
            read_regular_file(&path, 6, "test settings").expect("bounded read"),
            b"second"
        );
        assert!(read_regular_file(&path, 5, "test settings").is_err());
    }

    #[test]
    fn wallpaper_is_decoded_and_reencoded_as_bounded_jpeg() {
        let path = temporary_png(96, 72);
        let (bytes, width, height) = encode_wallpaper(&path).expect("sanitize wallpaper");
        let _ = fs::remove_file(path);

        assert_eq!((width, height), (96, 72));
        assert_eq!(
            image::guess_format(&bytes).expect("encoded format"),
            ImageFormat::Jpeg
        );
    }

    #[test]
    fn wallpaper_rejects_tiny_dimensions_before_use() {
        let path = temporary_png(32, 32);
        let result = encode_wallpaper(&path);
        let _ = fs::remove_file(path);

        assert!(result.is_err());
    }
}
