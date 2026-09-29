//! Native desktop identity. Only initialized when the GUI is launched.
use std::{path::Path, sync::Arc};

pub const APP_ID: &str = "org.mongodb.kingfisher";
const ICON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wizard-icon.png"));

pub fn window_icon() -> Arc<image::RgbaImage> {
    Arc::new(image::load_from_memory(ICON).expect("embedded wizard icon must decode").into_rgba8())
}

pub fn initialize(executable: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use objc2::{AnyThread, MainThreadMarker};
        use objc2_app_kit::{NSApplication, NSImage};
        use objc2_foundation::NSData;
        let main = MainThreadMarker::new().expect("wizard runs on the main thread");
        let image = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(ICON))
            .ok_or_else(|| anyhow::anyhow!("could not decode the Dock icon"))?;
        // SAFETY: A valid, non-null image is supplied on AppKit's main thread.
        unsafe {
            NSApplication::sharedApplication(main).setApplicationIconImage(Some(&image));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let directory = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::home_dir().map(|home| home.join(".local").join("share")))
            .ok_or_else(|| anyhow::anyhow!("no user data directory for the desktop icon"))?;
        install_linux_identity(&directory, executable)?;
    }
    let _ = executable;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn install_linux_identity(directory: &Path, executable: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    let executable =
        executable.to_str().ok_or_else(|| anyhow::anyhow!("desktop launcher path is not UTF-8"))?;
    anyhow::ensure!(
        !executable.chars().any(|c| c.is_control() || c == '='),
        "desktop launcher path contains unsupported characters"
    );
    // Desktop Entry string escaping is applied before Exec argument unquoting.
    // https://specifications.freedesktop.org/desktop-entry-spec/latest/exec-variables.html
    let escaped = executable
        .replace('\\', "\\\\\\\\")
        .replace('"', "\\\\\"")
        .replace('`', "\\\\`")
        .replace('$', "\\\\$")
        .replace('%', "%%");
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Kingfisher\nComment=Scan and inspect secret findings\nExec=\"{escaped}\" wizard\nIcon={APP_ID}\nTerminal=false\nCategories=Development;Utility;\nStartupWMClass={APP_ID}\n"
    );
    let icon = directory.join("icons/hicolor/512x512/apps").join(format!("{APP_ID}.png"));
    let desktop = directory.join("applications").join(format!("{APP_ID}.desktop"));
    for (path, bytes) in [(icon, ICON), (desktop, entry.as_bytes())] {
        let parent = path.parent().expect("desktop asset has a parent");
        std::fs::create_dir_all(parent)?;
        if std::fs::read(&path).ok().as_deref() == Some(bytes) {
            continue;
        }
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.persist(path).map_err(|error| error.error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_icon_is_square_and_has_transparency() {
        let icon = window_icon();
        assert_eq!(icon.dimensions(), (512, 512));
        assert!(icon.pixels().any(|pixel| pixel[3] == 0));
        assert!(icon.pixels().any(|pixel| pixel[3] != 0));
    }

    #[test]
    fn linux_identity_quotes_paths_and_installs_matching_assets() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("space $quote\"percent%back`slash\\kingfisher");
        install_linux_identity(directory.path(), &executable).unwrap();
        let entry = std::fs::read_to_string(
            directory.path().join("applications").join(format!("{APP_ID}.desktop")),
        )
        .unwrap();
        assert!(
            entry.contains("\\\\$quote\\\\\"percent%%back\\\\`slash\\\\\\\\kingfisher\" wizard")
        );
        assert!(entry.contains(&format!("Icon={APP_ID}\n")));
        assert_eq!(
            std::fs::read(
                directory.path().join("icons/hicolor/512x512/apps").join(format!("{APP_ID}.png"))
            )
            .unwrap(),
            ICON
        );
        install_linux_identity(directory.path(), &executable).unwrap();
        assert!(
            install_linux_identity(directory.path(), &directory.path().join("bad\npath")).is_err()
        );
    }
}
