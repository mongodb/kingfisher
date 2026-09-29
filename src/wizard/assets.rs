//! Add the wizard's Lucide icons to GPUI's smaller default component bundle.
use gpui_kit::{AssetSource, SharedString};
use std::borrow::Cow;

gpui_kit::assets::icon_assets!(
    WizardIcons,
    [
        ChartColumn,
        CircleAlert,
        Download,
        FolderGit2,
        Folders,
        KeyRound,
        Scan,
        ShieldCheck,
        SlidersHorizontal,
        Square,
        Terminal,
        X
    ]
);
pub struct Assets;
impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = WizardIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit::assets::Assets.load(path)
    }
    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(WizardIcons.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::assets::IconName;
    #[test]
    fn all_wizard_icons_are_embedded() {
        for icon in [
            IconName::ArrowRight,
            IconName::ChartColumn,
            IconName::ChevronDown,
            IconName::ChevronRight,
            IconName::CircleAlert,
            IconName::Copy,
            IconName::Download,
            IconName::FileText,
            IconName::FolderGit2,
            IconName::FolderOpen,
            IconName::Folders,
            IconName::Globe,
            IconName::Info,
            IconName::KeyRound,
            IconName::LayoutDashboard,
            IconName::Network,
            IconName::Play,
            IconName::Plus,
            IconName::Scan,
            IconName::ShieldCheck,
            IconName::SlidersHorizontal,
            IconName::Square,
            IconName::Terminal,
            IconName::X,
        ] {
            assert!(Assets.load(&icon.path()).unwrap().is_some(), "{icon:?}");
        }
    }
}
