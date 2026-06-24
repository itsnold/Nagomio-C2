fn main() {
    normalize_icon();
    tauri_build::build();
}

fn normalize_icon() {
    let icon_path = std::path::Path::new("icons/icon.png");
    let Ok(image) = image::open(icon_path) else {
        return;
    };

    if image.color().has_alpha() {
        return;
    }

    let rgba_image = image.to_rgba8();
    let _ = rgba_image.save(icon_path);
}
