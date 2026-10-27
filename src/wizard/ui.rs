use super::{
    process::{
        Process, Report, ScanOptions, ScanOutcome, Shell, command_preview, report_command_preview,
        viewer_command,
    },
    report::{FindingColumn, ReportData, number, sort_findings, text},
};
use gpui_kit::{
    App, AppContext, Bounds, ClipboardItem, Context, Div, Entity, FontWeight, Hsla, Image,
    ImageFormat, KeyBinding, Menu, MenuItem, PathPromptOptions, Render, TestSupportExt,
    TitlebarOptions, Window, WindowBounds, WindowOptions,
    assets::IconName,
    component::{
        ActiveTheme, Disableable, Icon, Root, Sizable, Theme, ThemeMode,
        button::{Button, ButtonVariants},
        checkbox::Checkbox,
        input::{Input, InputState},
        menu::{DropdownMenu, PopupMenuItem},
        scroll::{Scrollbar, ScrollbarMode},
        text::TextView,
    },
    div, img,
    prelude::*,
    px, relative, rems, size, uniform_list,
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const BG: u32 = 0x1e1f22;
const PANEL: u32 = 0x292b2f;
const INSET: u32 = 0x191a1d;
const BORDER: u32 = 0x3b3d42;
const TEXT: u32 = 0xebecf0;
const MUTED: u32 = 0x9b9ea6;
const AMBER: u32 = 0xe0af68;
const BLUE: u32 = 0x65a7ff;
const GREEN: u32 = 0x9ece6a;
const RED: u32 = 0xf7768e;
fn scan_rate(progress: &serde_json::Value) -> f64 {
    let seconds = progress["scan_seconds"].as_f64().unwrap_or(0.);
    if seconds > 0. { progress["bytes"].as_u64().unwrap_or(0) as f64 / 1e6 / seconds } else { 0. }
}
thread_local! {
    static LIGHT_PALETTE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn color(value: u32) -> Hsla {
    let value = if LIGHT_PALETTE.get() {
        match value {
            BG => 0xf7f8fa,
            PANEL => 0xffffff,
            INSET => 0xeff1f5,
            BORDER => 0xc9cdd5,
            TEXT => 0x20242c,
            MUTED => 0x596170,
            BLUE => 0x165dcc,
            GREEN => 0x377521,
            RED => 0xb42343,
            AMBER => 0x865800,
            other => other,
        }
    } else {
        value
    };
    gpui_kit::rgb(value).into()
}
fn column() -> Div {
    div().flex().flex_col()
}
fn row() -> Div {
    div().flex().items_center()
}
fn label(text: impl Into<gpui_kit::SharedString>) -> Div {
    div().text_xs().text_color(color(MUTED)).child(text.into())
}
fn icon(name: IconName) -> Icon {
    Icon::new(name).size_4()
}
fn heading(name: &str, description: &str) -> Div {
    column()
        .gap_1()
        .child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(name.to_owned()))
        .child(div().text_sm().text_color(color(MUTED)).child(description.to_owned()))
}
fn panel() -> Div {
    column().gap_3().p_4().bg(color(PANEL)).border_1().border_color(color(BORDER)).rounded_lg()
}

// Escape report content before rendering rich text: secrets must remain literal text.
fn selectable(id: impl Into<gpui_kit::ElementId>, value: impl AsRef<str>) -> TextView {
    let escaped = value.as_ref().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    TextView::html(id, format!("<pre>{escaped}</pre>")).selectable(true).scrollable(false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Scan,
    Overview,
    Findings,
    Coverage,
    Access,
    Activity,
}
impl Tab {
    fn label(self) -> &'static str {
        match self {
            Self::Scan => "New scan",
            Self::Overview => "Overview",
            Self::Findings => "Findings",
            Self::Coverage => "Coverage",
            Self::Access => "Blast radius",
            Self::Activity => "Activity",
        }
    }
    fn icon(self) -> IconName {
        match self {
            Self::Scan => IconName::Scan,
            Self::Overview => IconName::LayoutDashboard,
            Self::Findings => IconName::KeyRound,
            Self::Coverage => IconName::Folders,
            Self::Access => IconName::Network,
            Self::Activity => IconName::Terminal,
        }
    }
}
gpui_kit::actions!(kingfisher_wizard, [Quit]);
struct Scan {
    process: Process,
    report: Arc<Report>,
    progress: serde_json::Value,
}
struct Viewer {
    process: Process,
    _report: Arc<Report>,
}
struct AdvancedOption {
    spec: super::options::OptionSpec,
    input: Entity<InputState>,
    enabled: bool,
}
#[derive(Clone)]
struct ReportState {
    data: Option<Arc<ReportData>>,
    report: Option<Arc<Report>>,
    search: Entity<InputState>,
    filters: Vec<(String, Entity<InputState>)>,
    visible_filters: Vec<usize>,
    raw_open: bool,
    active_only: bool,
    unique: bool,
    filtered: Vec<usize>,
    finding_sort: Option<(FindingColumn, bool)>,
    columns: Vec<(FindingColumn, f32)>,
    horizontal_scroll: gpui_kit::ScrollHandle,
    inspector_scroll: gpui_kit::ScrollHandle,
    findings_scroll: gpui_kit::UniformListScrollHandle,
    selected: Option<usize>,
    detail: String,
    tab: Tab,
}
struct ReportTab {
    id: u64,
    title: String,
    state: ReportState,
}
struct Desktop {
    window: gpui_kit::AnyWindowHandle,
    reports: Vec<ReportTab>,
    active_report: Option<u64>,
    next_report_id: u64,

    executable: PathBuf,
    logo: Arc<Image>,
    target: Entity<InputState>,
    selected_path: Option<(String, PathBuf)>,
    rule: Entity<InputState>,
    exclude: Entity<InputState>,
    search: Entity<InputState>,
    visible_filters: Vec<usize>,
    raw_open: bool,
    builtins: bool,
    rule_paths: Vec<PathBuf>,
    settings_group: String,
    filters: Vec<(String, Entity<InputState>)>,
    advanced: bool,
    option_search: Entity<InputState>,
    advanced_options: Vec<AdvancedOption>,
    history: bool,
    validate: bool,
    access_map: bool,
    redact: bool,
    shell: Shell,
    tab: Tab,
    active_only: bool,
    unique: bool,
    scan: Option<Scan>,
    report: Option<Arc<Report>>,
    data: Option<Arc<ReportData>>,
    viewers: Vec<Viewer>,
    filtered: Vec<usize>,
    finding_sort: Option<(FindingColumn, bool)>,
    theme_mode: Option<ThemeMode>,
    columns: Vec<(FindingColumn, f32)>,
    resizing: Option<(usize, gpui_kit::Pixels, f32)>,
    horizontal_scroll: gpui_kit::ScrollHandle,
    inspector_scroll: gpui_kit::ScrollHandle,
    findings_focus: gpui_kit::FocusHandle,
    findings_scroll: gpui_kit::UniformListScrollHandle,
    selected: Option<usize>,
    detail: String,
    log_scroll: gpui_kit::UniformListScrollHandle,
    follow_log: bool,
    status: String,
    notice: String,
    error: Option<String>,
    activity: String,
    loading: bool,
    pending_loads: usize,
}
impl Desktop {
    fn new(
        executable: PathBuf,
        initial: Option<OsString>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let target = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Choose a folder, file, or repository URL")
        });
        let selected_path = initial.map(|value| {
            let path = PathBuf::from(value);
            let display = path.to_string_lossy().into_owned();
            target.update(cx, |state, cx| state.set_value(display.clone(), window, cx));
            (display, path)
        });
        let rule = cx.new(|cx| InputState::new(window, cx).placeholder("All detectors"));
        let exclude = cx.new(|cx| InputState::new(window, cx).placeholder("e.g. **/vendor/**"));
        let (search, filters) = Self::report_inputs(window, cx);
        let option_search =
            cx.new(|cx| InputState::new(window, cx).placeholder("Search all settings…"));
        let advanced_options = super::options::catalog()
            .into_iter()
            .map(|spec| {
                let input =
                    cx.new(|cx| InputState::new(window, cx).placeholder(spec.placeholder.clone()));
                cx.observe(&input, |_, _, cx| cx.notify()).detach();
                AdvancedOption { spec, input, enabled: false }
            })
            .collect();
        for input in [&target, &rule, &exclude, &option_search] {
            cx.observe(input, |_, _, cx| cx.notify()).detach();
        }
        cx.on_app_quit(|this, _| {
            this.scan = None;
            this.viewers.clear();
            this.report = None;
            async {}
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_millis(500)).await;
                if this.update(cx, |this, cx| this.poll(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        cx.observe_window_appearance(window, |this, window, cx| {
            if this.theme_mode.is_none() {
                Theme::sync_system_appearance(Some(window), cx);
                configure_theme(cx);
                cx.notify();
            }
        })
        .detach();
        Self {
            window: window.window_handle(),
            reports: Vec::new(),
            active_report: None,
            next_report_id: 0,
            executable,
            logo: Arc::new(Image::from_bytes(
                ImageFormat::Png,
                include_bytes!("../../docs/viewer/kingfisher_logo.png").to_vec(),
            )),
            target,
            selected_path,
            rule,
            exclude,
            search,
            visible_filters: Vec::new(),
            raw_open: false,
            builtins: true,
            rule_paths: Vec::new(),
            settings_group: "Scan".into(),
            filters,
            advanced: false,
            option_search,
            advanced_options,
            history: true,
            validate: true,
            access_map: false,
            redact: false,
            shell: Shell::native(),
            tab: Tab::Scan,
            active_only: false,
            unique: true,
            scan: None,
            report: None,
            data: None,
            viewers: Vec::new(),
            filtered: Vec::new(),
            finding_sort: None,
            theme_mode: None,
            columns: FindingColumn::ALL[..4].iter().map(|c| (*c, c.width())).collect(),
            resizing: None,
            horizontal_scroll: gpui_kit::ScrollHandle::default(),
            inspector_scroll: gpui_kit::ScrollHandle::default(),
            findings_focus: cx.focus_handle(),
            findings_scroll: gpui_kit::UniformListScrollHandle::default(),
            selected: None,
            detail: String::new(),
            log_scroll: gpui_kit::UniformListScrollHandle::default(),
            follow_log: true,
            status: "Ready to scan".into(),
            notice: String::new(),
            error: None,
            activity: String::new(),
            loading: false,
            pending_loads: 0,
        }
    }
    fn report_inputs(
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (Entity<InputState>, Vec<(String, Entity<InputState>)>) {
        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Search rules, paths, status, or snippets…")
        });
        let filters = [
            "Status",
            "Rule",
            "Path",
            "Repository",
            "Author / committer",
            "Commit",
            "From date",
            "To date",
        ]
        .into_iter()
        .map(|name| {
            let input = cx.new(|cx| {
                InputState::new(window, cx).placeholder(match name {
                    "Status" => "Exact status, e.g. Active Credential",
                    "From date" | "To date" => "YYYY-MM-DD",
                    _ => "Contains…",
                })
            });
            cx.observe(&input, |this: &mut Self, _, cx| {
                this.refilter(cx);
                cx.notify();
            })
            .detach();
            (name.to_owned(), input)
        })
        .collect();
        cx.observe(&search, |this, _, cx| {
            this.refilter(cx);
            cx.notify();
        })
        .detach();
        (search, filters)
    }
    fn report_state(&self) -> ReportState {
        ReportState {
            data: self.data.clone(),
            report: self.report.clone(),
            search: self.search.clone(),
            filters: self.filters.clone(),
            visible_filters: self.visible_filters.clone(),
            raw_open: self.raw_open,
            active_only: self.active_only,
            unique: self.unique,
            filtered: self.filtered.clone(),
            finding_sort: self.finding_sort,
            columns: self.columns.clone(),
            horizontal_scroll: self.horizontal_scroll.clone(),
            inspector_scroll: self.inspector_scroll.clone(),
            findings_scroll: self.findings_scroll.clone(),
            selected: self.selected,
            detail: self.detail.clone(),
            tab: self.tab,
        }
    }
    fn save_report_state(&mut self) {
        if matches!(self.tab, Tab::Scan | Tab::Activity) {
            return;
        }
        if let Some(index) = self.reports.iter().position(|tab| Some(tab.id) == self.active_report)
        {
            self.reports[index].state = self.report_state();
        }
    }
    fn switch_report(&mut self, id: u64, cx: &mut Context<Self>) {
        if self.active_report == Some(id) && !matches!(self.tab, Tab::Scan | Tab::Activity) {
            return;
        }
        let Some(index) = self.reports.iter().position(|tab| tab.id == id) else {
            return;
        };
        self.save_report_state();
        let state = self.reports[index].state.clone();
        self.data = state.data;
        self.report = state.report;
        self.search = state.search;
        self.filters = state.filters;
        self.visible_filters = state.visible_filters;
        self.raw_open = state.raw_open;
        self.active_only = state.active_only;
        self.unique = state.unique;
        self.filtered = state.filtered;
        self.finding_sort = state.finding_sort;
        self.columns = state.columns;
        self.horizontal_scroll = state.horizontal_scroll;
        self.inspector_scroll = state.inspector_scroll;
        self.findings_scroll = state.findings_scroll;
        self.selected = state.selected;
        self.detail = state.detail;
        self.tab = state.tab;
        self.active_report = Some(id);
        self.resizing = None;
        self.report_notice();
        cx.notify();
    }
    fn report_notice(&mut self) {
        self.notice = if self.report.is_some() {
            "Temporary scan report · export to keep"
        } else {
            "Report loaded locally"
        }
        .into();
        if self.scan.is_none() {
            self.status = format!(
                "Report ready · {} findings",
                number(self.data.as_ref().map_or(0, |d| d.findings.len()))
            );
        }
    }
    fn close_report(&mut self, id: u64, window: &mut Window, cx: &mut Context<Self>) {
        let Some(index) = self.reports.iter().position(|tab| tab.id == id) else {
            return;
        };
        self.reports.remove(index);
        if self.active_report == Some(id) {
            self.active_report = None;
            if let Some(next) = self.reports.get(index.min(self.reports.len().saturating_sub(1))) {
                self.switch_report(next.id, cx);
            } else {
                self.reset_report(window, cx);
                self.data = None;
                self.report = None;
                self.tab = Tab::Scan;
                self.notice.clear();
                if self.scan.is_none() {
                    self.status = "Ready to scan".into();
                }
            }
        }
        cx.notify();
    }
    fn reset_report(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        (self.search, self.filters) = Self::report_inputs(window, cx);
        self.visible_filters.clear();
        self.raw_open = false;
        self.active_only = false;
        self.unique = true;
        self.filtered.clear();
        self.finding_sort = None;
        self.columns = FindingColumn::ALL[..4].iter().map(|c| (*c, c.width())).collect();
        self.horizontal_scroll = Default::default();
        self.inspector_scroll = Default::default();
        self.findings_scroll = Default::default();
        self.resizing = None;
        self.selected = None;
        self.detail.clear();
    }
    fn add_report(
        &mut self,
        data: ReportData,
        report: Option<Arc<Report>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.save_report_state();
        self.reset_report(window, cx);
        self.next_report_id += 1;
        let title = if report.is_some() {
            format!("Scan {}", number(self.next_report_id))
        } else {
            data.sources
                .first()
                .and_then(|p| p.file_name())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Report".into())
        };
        self.data = Some(Arc::new(data));
        self.report = report;
        self.tab = Tab::Overview;
        self.refilter(cx);
        self.active_report = Some(self.next_report_id);
        self.reports.push(ReportTab { id: self.next_report_id, title, state: self.report_state() });
        self.report_notice();
        cx.notify();
    }
    fn report_tabs(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        row()
            .id("report-tabs")
            .overflow_x_scroll()
            .flex_shrink_0()
            .px_4()
            .py_2()
            .gap_2()
            .border_b_1()
            .border_color(color(BORDER))
            .children(self.reports.iter().map(|tab| {
                let id = tab.id;
                row()
                    .flex_shrink_0()
                    .gap_1()
                    .rounded_md()
                    .bg(color(if self.active_report == Some(id) { PANEL } else { BG }))
                    .child(
                        Button::new(("report-tab", id))
                            .ghost()
                            .small()
                            .label(tab.title.clone())
                            .tooltip(
                                tab.state
                                    .data
                                    .as_ref()
                                    .map(|data| {
                                        data.sources
                                            .iter()
                                            .map(|p| p.display().to_string())
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    })
                                    .unwrap_or_default(),
                            )
                            .when(self.active_report == Some(id), |button| button.primary())
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.switch_report(id, cx)),
                            ),
                    )
                    .child(
                        Button::new(("close-report", id))
                            .ghost()
                            .xsmall()
                            .icon(IconName::X)
                            .tooltip("Close report")
                            .accessibility_label(format!("Close {}", tab.title))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.close_report(id, window, cx)
                            })),
                    )
            }))
    }
    fn options(&self, cx: &App) -> ScanOptions {
        let text = self.target.read(cx).value().to_string();
        let target = self
            .selected_path
            .as_ref()
            .filter(|(display, _)| display == &text)
            .map(|(_, path)| path.as_os_str().to_owned())
            .unwrap_or_else(|| text.into());
        ScanOptions {
            target,
            extra: self
                .advanced_options
                .iter()
                .filter_map(|option| {
                    let value = option.input.read(cx).value();
                    if option.spec.boolean {
                        option.enabled.then(|| OsString::from(format!("--{}", option.spec.flag)))
                    } else if value.trim().is_empty() {
                        None
                    } else if option.spec.flag == "verbose" {
                        match value.as_ref() {
                            "0" => None,
                            "1" => Some("-v".into()),
                            "2" => Some("-vv".into()),
                            "3" => Some("-vvv".into()),
                            _ => Some(format!("--verbose={value}").into()),
                        }
                    } else {
                        Some(OsString::from(format!("--{}={}", option.spec.flag, value)))
                    }
                })
                .chain((!self.builtins).then(|| OsString::from("--load-builtins=false")))
                .chain(self.rule_paths.iter().map(|path| {
                    let mut arg = OsString::from("--rules-path=");
                    arg.push(path);
                    arg
                }))
                .collect(),
            history: self.history,
            validate: self.validate,
            access_map: self.access_map,
            redact: self.redact,
            rule: self.rule.read(cx).value().to_string(),
            exclude: self.exclude.read(cx).value().to_string(),
        }
    }
    fn preview(&self, cx: &App) -> anyhow::Result<String> {
        if !self.builtins && self.rule_paths.is_empty() {
            anyhow::bail!("Add custom rules or enable the built-in catalog.");
        }
        command_preview(
            &self
                .options(cx)
                .command(Path::new("kingfisher"), Path::new("kingfisher-report.json"))?,
            self.shell,
        )
    }
    fn append(&mut self, text: &str) {
        self.activity.push_str(text);
        if self.activity.len() > 512_000 {
            let mut boundary = self.activity.len() - 512_000;
            while !self.activity.is_char_boundary(boundary) {
                boundary += 1;
            }
            self.activity.drain(..boundary);
        }
        if self.follow_log {
            self.log_scroll.scroll_to_item(
                self.activity.lines().count().saturating_sub(1),
                gpui_kit::ScrollStrategy::Bottom,
            );
        }
    }
    fn fail(&mut self, error: impl std::fmt::Display, cx: &mut Context<Self>) {
        let message = error.to_string();
        self.append(&format!("\nERROR: {message}\n"));
        self.notice.clear();
        self.error = Some(message);
        self.status = "Action failed".into();
        self.save_report_state();
        self.tab = Tab::Activity;
        cx.notify();
    }
    fn start(&mut self, cx: &mut Context<Self>) {
        if !self.builtins && self.rule_paths.is_empty() {
            self.fail(anyhow::anyhow!("Add custom rules or enable the built-in catalog."), cx);
            return;
        }
        if self.scan.is_some() || self.loading {
            return;
        }
        self.error = None;
        self.notice.clear();
        self.activity.clear();
        let result = (|| -> anyhow::Result<Scan> {
            let report = Arc::new(Report::new()?);
            let mut command = self.options(cx).command(&self.executable, &report.path)?;
            command.env("KINGFISHER_PROGRESS_FILE", report.directory.path().join("progress.json"));
            // CLI-managed temporary clones stay inside our private job directory. There is no
            // extra clone-dir CLI option, and cancellation still removes the job's artifacts.
            for variable in ["TMPDIR", "TMP", "TEMP"] {
                command.env(variable, report.directory.path());
            }
            self.append(&format!(
                "Starting scan (report stored temporarily; use Export JSON to keep it).\nEquivalent terminal command:\n{}\n\n",
                self.preview(cx).unwrap_or_else(|_| {
                    "Running the selected native path (not representable as a shell command)."
                        .into()
                })
            ));
            Ok(Scan {
                process: Process::spawn(command)?,
                report,
                progress: serde_json::Value::Null,
            })
        })();
        match result {
            Ok(scan) => {
                self.scan = Some(scan);
                self.status = "Scanning".into();
                self.tab = Tab::Activity;
            }
            Err(error) => self.fail(format!("{error:#}"), cx),
        }
        cx.notify();
    }
    fn cancel(&mut self, cx: &mut Context<Self>) {
        if let Some(scan) = self.scan.as_mut() {
            match scan.process.cancel() {
                Ok(()) => {
                    self.scan = None;
                    self.status = "Scan cancelled".into();
                    self.append("\nScan cancelled. Partial report discarded.\n");
                }
                Err(error) => self.fail(error, cx),
            }
        }
        cx.notify();
    }
    fn poll(&mut self, cx: &mut Context<Self>) {
        let mut logs = Vec::new();
        let mut changed = false;
        if let Some(scan) = self.scan.as_mut() {
            let elapsed = scan.process.started.elapsed().as_secs_f64();
            if self.status == "Scanning" || self.status.starts_with("Preparing scanner") {
                self.status = format!(
                    "Preparing scanner and rules · {}s elapsed",
                    number(format!("{elapsed:.0}"))
                );
            }
            if let Ok(bytes) = std::fs::read(scan.report.directory.path().join("progress.json"))
                && let Ok(progress) = serde_json::from_slice::<serde_json::Value>(&bytes)
            {
                let old_phase = scan.progress["phase"].as_str().unwrap_or("");
                let phase = progress["phase"].as_str().unwrap_or("Preparing scan");
                if phase != old_phase {
                    logs.push(format!("\n── {phase} ──\n"));
                }
                scan.progress = progress.clone();
                let bytes = progress["bytes"].as_u64().unwrap_or(0) as f64;
                let total = progress["total"].as_u64().unwrap_or(0);
                let completed = progress["completed"].as_u64().unwrap_or(0);
                self.status = format!(
                    "{}{} · {} GB scanned · {} blobs{} · {}s",
                    progress["phase"].as_str().unwrap_or("Scanning"),
                    if total > 0 {
                        format!(" {}/{}", number(completed), number(total))
                    } else {
                        String::new()
                    },
                    number(format!("{:.3}", bytes / 1e9)),
                    number(progress["blobs"].as_u64().unwrap_or(0)),
                    if progress["kind"] == "scan" {
                        format!(" · {} MB/s", number(format!("{:.1}", scan_rate(&progress))))
                    } else {
                        String::new()
                    },
                    number(format!("{elapsed:.0}"))
                );
            }
            let completion = scan.process.poll();
            logs.extend(scan.process.logs.drain());
            changed = true;
            if let Some(completion) = completion.transpose() {
                let scan = self.scan.take().unwrap();
                match completion.and_then(ScanOutcome::from_status) {
                    Ok(outcome) => {
                        self.status = format!(
                            "{} · {}s",
                            outcome.label(),
                            number(scan.process.started.elapsed().as_secs())
                        );
                        self.append(&format!("\n{}\n", self.status));
                        if outcome != ScanOutcome::NoInputs {
                            self.load(vec![scan.report.path.clone()], Some(scan.report), cx);
                        }
                    }
                    Err(error) => self.fail(error, cx),
                }
            }
        }
        let mut viewer_error = None;
        self.viewers.retain_mut(|viewer| {
            let result = viewer.process.poll();
            logs.extend(viewer.process.logs.drain());
            match result {
                Ok(None) => true,
                Ok(Some(status)) => {
                    if !status.success() {
                        viewer_error = Some(format!("Local web viewer exited with {status}"));
                    }
                    false
                }
                Err(e) => {
                    viewer_error = Some(e.to_string());
                    false
                }
            }
        });
        for log in logs {
            self.append(&log);
            changed = true;
        }
        if let Some(error) = viewer_error {
            self.fail(error, cx);
        }
        if changed {
            cx.notify();
        }
    }
    fn load(&mut self, paths: Vec<PathBuf>, report: Option<Arc<Report>>, cx: &mut Context<Self>) {
        self.pending_loads += 1;
        self.loading = true;
        self.error = None;
        for path in &paths {
            self.append(&format!("Loading report: {}\n", path.display()));
        }
        let window = self.window;
        cx.spawn(async move |this, cx| {
            let results = cx
                .background_executor()
                .spawn(async move {
                    paths.into_iter().map(|path| ReportData::load(&[path])).collect::<Vec<_>>()
                })
                .await;
            let _ = cx.update_window(window, |_, window, cx| {
                this.update(cx, |this, cx| {
                    this.pending_loads = this.pending_loads.saturating_sub(1);
                    this.loading = this.pending_loads > 0;
                    for result in results {
                        match result {
                            Ok(data) => {
                                this.append(&format!(
                                    "Loaded {} findings, {} repositories, {} identities.\n",
                                    number(data.findings.len()),
                                    number(data.coverage.len()),
                                    number(data.identities.len())
                                ));
                                this.add_report(data, report.clone(), window, cx);
                            }
                            Err(error) => this.fail(format!("{error:#}"), cx),
                        }
                    }
                    cx.notify();
                })
            });
        })
        .detach();
        cx.notify();
    }
    fn refilter(&mut self, cx: &App) {
        self.filtered = self
            .data
            .as_ref()
            .map(|data| {
                data.filtered_by(
                    &self.search.read(cx).value(),
                    self.active_only,
                    self.unique,
                    &self
                        .filters
                        .iter()
                        .map(|(name, input)| (name.clone(), input.read(cx).value().to_string()))
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();
        if let Some((column, descending)) = self.finding_sort
            && let Some(data) = &self.data
        {
            sort_findings(&mut self.filtered, &data.findings, column, descending);
        }
        if self.selected.is_some_and(|i| !self.filtered.contains(&i)) {
            self.selected = None;
            self.detail.clear();
        }
    }
    fn choose(&mut self, report: bool, window: &mut Window, cx: &mut Context<Self>) {
        let chosen = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: !report,
            multiple: report,
            prompt: Some(if report { "Open reports" } else { "Scan this path" }.into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = chosen.await;
            let _ = this.update_in(cx, |this, window, cx| {
                match result {
                    Ok(Ok(Some(paths))) => {
                        if report {
                            this.load(paths, None, cx);
                        } else if this.scan.is_none()
                            && let Some(path) = paths.into_iter().next()
                        {
                            let display = path.to_string_lossy().into_owned();
                            this.target.update(cx, |input, cx| {
                                input.set_value(display.clone(), window, cx)
                            });
                            this.selected_path = Some((display, path));
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => this.fail(error, cx),
                    Err(error) => this.fail(error, cx),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn save(&mut self, filtered: bool, cx: &mut Context<Self>) {
        let Some(data) = self.data.clone() else {
            return;
        };
        let indices = filtered.then(|| self.filtered.clone());
        let chosen = cx.prompt_for_new_path(
            &std::env::home_dir().unwrap_or_else(|| PathBuf::from(".")),
            Some("kingfisher-report.json"),
        );
        cx.spawn(async move |this, cx| {
            let result = async {
                let Some(path) = chosen.await?? else {
                    return Ok::<_, anyhow::Error>(None);
                };
                cx.background_executor()
                    .spawn(async move {
                        data.export(&path, indices.as_deref())?;
                        Ok(Some(path))
                    })
                    .await
            }
            .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(Some(path)) => this.notice = format!("Saved {}", path.display()),
                    Ok(None) => {}
                    Err(e) => this.fail(e, cx),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn browser(&mut self, cx: &mut Context<Self>) {
        let Some(data) = self.data.clone() else {
            return;
        };
        let executable = self.executable.clone();
        let imported = self.report.is_none();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let report = Arc::new(Report::new()?);
                    let command = if imported && !data.sources.is_empty() {
                        // Let the web viewer import the original formats (including SARIF)
                        // with their full source context, rather than a normalized export.
                        let mut paths = Vec::new();
                        for (index, source) in data.sources.iter().enumerate() {
                            // The viewer accepts JSON content by extension. Native report
                            // loading also accepts extensionless files, so stage each source.
                            let path = report.directory.path().join(format!("source-{index}.json"));
                            std::fs::copy(source, &path)?;
                            paths.push(path);
                        }
                        let mut command = viewer_command(&executable, &paths[0]);
                        command.args(&paths[1..]);
                        command
                    } else {
                        data.export(&report.path, None)?;
                        viewer_command(&executable, &report.path)
                    };
                    let process = Process::spawn(command)?;
                    Ok::<_, anyhow::Error>(Viewer { process, _report: report })
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(viewer) => this.viewers.push(viewer),
                    Err(e) => this.fail(e, cx),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn copy(&mut self, text: String, message: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.notice = message.into();
        cx.notify();
    }
    fn navigate(&mut self, tab: Tab, cx: &mut Context<Self>) {
        if matches!(self.tab, Tab::Scan | Tab::Activity)
            && !matches!(tab, Tab::Scan | Tab::Activity)
            && let Some(id) = self.active_report
        {
            self.switch_report(id, cx);
        }
        if matches!(tab, Tab::Scan | Tab::Activity) {
            self.save_report_state();
        } else if self.tab != tab {
            self.selected = None;
            self.detail.clear();
        }
        self.tab = tab;
        cx.notify();
    }
    fn choose_rules(&mut self, directories: bool, window: &mut Window, cx: &mut Context<Self>) {
        let chosen = cx.prompt_for_paths(PathPromptOptions {
            files: !directories,
            directories,
            multiple: true,
            prompt: Some(if directories { "Add rules folder" } else { "Add rule files" }.into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = chosen.await;
            let _ = this.update_in(cx, |this, _, cx| {
                match result {
                    Ok(Ok(Some(paths))) if this.scan.is_none() => {
                        for path in paths {
                            if !this.rule_paths.contains(&path) {
                                this.rule_paths.push(path);
                            }
                        }
                    }
                    Ok(Err(error)) => this.fail(error, cx),
                    Err(error) => this.fail(error, cx),
                    _ => {}
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn rules_view(&self, busy: bool, cx: &mut Context<Self>) -> Div {
        panel()
            .child(
                row()
                    .gap_2()
                    .child(icon(IconName::ShieldCheck).text_color(color(BLUE)))
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Rules")),
            )
            .child(
                Checkbox::new("builtin-rules")
                    .label("Kingfisher built-in rules")
                    .checked(self.builtins)
                    .disabled(busy)
                    .on_click(cx.listener(|this, value, _, cx| {
                        this.builtins = *value;
                        cx.notify();
                    })),
            )
            .child(label("Use the maintained catalog, add custom rules, or combine both."))
            .children(self.rule_paths.iter().enumerate().map(|(index, path)| {
                row()
                    .gap_2()
                    .child(icon(if path.is_dir() {
                        IconName::FolderOpen
                    } else {
                        IconName::FileText
                    }))
                    .child(
                        column()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div().text_sm().truncate().child(
                                    path.file_name()
                                        .unwrap_or(path.as_os_str())
                                        .to_string_lossy()
                                        .into_owned(),
                                ),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(color(MUTED))
                                    .truncate()
                                    .child(path.to_string_lossy().into_owned()),
                            ),
                    )
                    .child(
                        Button::new(("remove-rules", index))
                            .ghost()
                            .small()
                            .icon(IconName::X)
                            .accessibility_label("Remove rules source")
                            .tooltip("Remove rules source")
                            .disabled(busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.rule_paths.remove(index);
                                cx.notify();
                            })),
                    )
            }))
            .child(
                row()
                    .gap_2()
                    .child(
                        Button::new("add-rule-files")
                            .small()
                            .icon(IconName::Plus)
                            .label("Rule files…")
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_rules(false, window, cx)
                            })),
                    )
                    .child(
                        Button::new("add-rule-folder")
                            .small()
                            .icon(IconName::FolderOpen)
                            .label("Rules folder…")
                            .disabled(busy)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_rules(true, window, cx)
                            })),
                    ),
            )
            .child(
                row().gap_3().child(div().w(rems(7.)).child(label("Limit to detector"))).child(
                    div().flex_1().min_w_0().child(
                        Input::new(&self.rule)
                            .id("rule-selector")
                            .aria_label("Rule selector")
                            .small()
                            .disabled(busy),
                    ),
                ),
            )
            .child(label("YAML or Betterleaks TOML · Folders include nested rule files"))
    }
    fn scan_view(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let busy = self.scan.is_some() || self.loading;
        let preview = self.preview(cx);
        let code = preview.as_ref().cloned().unwrap_or_else(|error| error.to_string());
        let can_copy = preview.is_ok();
        column().size_full()
            .child(row().px_4().py_3().gap_3().justify_between()
                .child(heading("New scan", "Choose a source and the rules to run."))
                .child(row().gap_2()
                    .child(Button::new("advanced-options").ghost().icon(IconName::SlidersHorizontal).label("Scan settings…")
                        .on_click(cx.listener(|this,_,_,cx|{this.advanced = !this.advanced;cx.notify();})))
                    .child(Button::new("start").primary().icon(IconName::Play).label("Start scan").disabled(busy)
                        .on_click(cx.listener(|this,_,_,cx|this.start(cx))))))
            .child(div().id("scan-scroll").test_support().flex_1().min_h_0().overflow_y_scroll()
            .child(row().items_start().w_full().gap_4().px_4().pb_4()
            .child(column().flex_1().min_w_0().gap_3()
                .child(panel().child(div().font_weight(FontWeight::SEMIBOLD).child("Source"))
                    .child(row().gap_2().child(div().flex_1().min_w_0().child(Input::new(&self.target).id("scan-target").aria_label("Scan target").disabled(busy)))
                        .child(Button::new("browse").icon(IconName::FolderOpen).label("Choose…").disabled(busy).on_click(cx.listener(|this,_,window,cx|this.choose(false,window,cx)))))
                    .child(label("Folder, file, or Git repository URL")))
                .child(self.rules_view(busy,cx))
                .child(panel()
                    .child(self.option("validation", "Validate credentials", "Check whether credentials are active.",self.validate,busy,|this,value|{this.validate=value;if !value{this.access_map=false;}},cx))
                    .child(self.option("history", "Include Git history", "Include secrets in past commits.",self.history,busy,|this,value|this.history=value,cx))
                    .child(self.option("mapping", "Map blast radius", "Discover permissions and reachable resources.",self.access_map,busy||!self.validate,|this,value|this.access_map=value,cx))
                    .child(self.option("redact", "Redact secret values", "Hide secret values in the report.",self.redact,busy,|this,value|this.redact=value,cx)))
                .when(cfg!(debug_assertions), |view|view.child(label("Debug build · use a release build for scan performance."))))
            .child(column().w(rems(28.)).flex_shrink_0().gap_3()
                .when(self.advanced, |view| view.child(self.advanced_view(cx)))
                .when(!self.advanced, |view| view.child(panel().bg(color(INSET))
                    .child(row().justify_between().child(div().font_weight(FontWeight::SEMIBOLD).child("Command preview"))
                        .child(Button::new("copy-command").ghost().small().icon(IconName::Copy).label("Copy").disabled(!can_copy)
                            .on_click(cx.listener(|this,_,_,cx|{match this.preview(cx){Ok(text)=>this.copy(text,"Command copied",cx),Err(e)=>this.fail(e,cx)}}))))
                    .child(row().gap_2().child(self.shell_button(Shell::Posix,cx)).child(self.shell_button(Shell::PowerShell,cx)))
                    .child(div().id("command").max_h(rems(28.)).overflow_y_scroll().text_sm().font_family(cx.theme().mono_font_family.clone()).text_color(color(TEXT)).child(code))
                    .child(label("Run here or copy to your terminal. Reports stay on your computer.")))))))
    }
    fn advanced_view(&self, cx: &mut Context<Self>) -> Div {
        let query = self.option_search.read(cx).value().to_lowercase();
        let busy = self.scan.is_some() || self.loading;
        let entity = cx.entity().downgrade();
        let group = self.settings_group.clone();
        panel()
            .child(
                row()
                    .justify_between()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Scan settings"))
                    .child(Button::new("close-settings").small().ghost().label("Done").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.advanced = false;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                Button::new("settings-category")
                    .label(group.clone())
                    .icon(IconName::ChevronDown)
                    .dropdown_menu(move |mut menu, _, _| {
                        for section in super::options::SECTIONS {
                            let entity = entity.clone();
                            let section = *section;
                            menu = menu.item(
                                PopupMenuItem::new(section).checked(section == group).on_click(
                                    move |_, window, cx| {
                                        let _ = entity.update(cx, |this, cx| {
                                            this.settings_group = section.into();
                                            this.option_search.update(cx, |state, cx| {
                                                state.set_value("", window, cx)
                                            });
                                            cx.notify();
                                        });
                                    },
                                ),
                            );
                        }
                        menu
                    }),
            )
            .child(
                Input::new(&self.option_search)
                    .id("option-search")
                    .small()
                    .aria_label("Search all settings"),
            )
            .child(label("Unset values use CLI defaults. Search covers every category."))
            .child(
                column()
                    .id("advanced-scroll")
                    .test_support()
                    .h(rems(25.))
                    .overflow_y_scroll()
                    .gap_2()
                    .when(query.is_empty() && self.settings_group == "Git & files", |view| {
                        view.child(
                            column().gap_1().child(label("Exclude paths")).child(
                                Input::new(&self.exclude)
                                    .id("exclude-paths")
                                    .small()
                                    .aria_label("Exclude paths")
                                    .disabled(busy),
                            ),
                        )
                    })
                    .children(
                        self.advanced_options
                            .iter()
                            .enumerate()
                            .filter(|(_, option)| {
                                if query.is_empty() {
                                    super::options::section(&option.spec) == self.settings_group
                                } else {
                                    format!(
                                        "{} {} {}",
                                        option.spec.flag,
                                        super::options::title(&option.spec.flag),
                                        option.spec.help
                                    )
                                    .to_lowercase()
                                    .contains(&query)
                                }
                            })
                            .map(|(index, option)| {
                                let title = super::options::title(&option.spec.flag);
                                let field = column()
                                    .gap_1()
                                    .py_2()
                                    .border_b_1()
                                    .border_color(color(BORDER));
                                if option.spec.boolean {
                                    field.child(
                                        Checkbox::new(("advanced-flag", index))
                                            .label(title)
                                            .tooltip(option.spec.help.clone())
                                            .checked(option.enabled)
                                            .disabled(busy)
                                            .on_click(cx.listener(move |this, value, _, cx| {
                                                this.advanced_options[index].enabled = *value;
                                                cx.notify();
                                            })),
                                    )
                                } else {
                                    let field = field.child(
                                        row()
                                            .justify_between()
                                            .gap_2()
                                            .child(div().text_sm().child(title))
                                            .child(
                                                Button::new(("setting-help", index))
                                                    .ghost()
                                                    .xsmall()
                                                    .icon(IconName::Info)
                                                    .tooltip(format!(
                                                        "{}\n--{}",
                                                        option.spec.help, option.spec.flag
                                                    )),
                                            ),
                                    );
                                    let field = if option.spec.choices.is_empty() {
                                        field.child(
                                            Input::new(&option.input)
                                                .id(("advanced-value", index))
                                                .small()
                                                .aria_label(option.spec.flag.clone())
                                                .disabled(busy),
                                        )
                                    } else {
                                        let value = option.input.read(cx).value().to_string();
                                        let choices = option.spec.choices.clone();
                                        let input = option.input.clone();
                                        field.child(
                                            Button::new(("setting-choice", index))
                                                .small()
                                                .label(if value.is_empty() {
                                                    "Default".into()
                                                } else {
                                                    value.clone()
                                                })
                                                .icon(IconName::ChevronDown)
                                                .disabled(busy)
                                                .dropdown_menu(move |mut menu, _, _| {
                                                    for choice in std::iter::once(String::new())
                                                        .chain(choices.clone())
                                                    {
                                                        let input = input.clone();
                                                        menu = menu.item(
                                                            PopupMenuItem::new(
                                                                if choice.is_empty() {
                                                                    "Default".into()
                                                                } else {
                                                                    choice.clone()
                                                                },
                                                            )
                                                            .checked(value == choice)
                                                            .on_click(move |_, window, cx| {
                                                                input.update(cx, |state, cx| {
                                                                    state.set_value(
                                                                        choice.clone(),
                                                                        window,
                                                                        cx,
                                                                    )
                                                                })
                                                            }),
                                                        );
                                                    }
                                                    menu
                                                }),
                                        )
                                    };
                                    field.when(option.spec.repeatable, |field| {
                                        field.child(
                                            Button::new(("repeat-option", index))
                                                .xsmall()
                                                .ghost()
                                                .icon(IconName::Plus)
                                                .label("Add value")
                                                .disabled(busy)
                                                .on_click(cx.listener(
                                                    move |this, _, window, cx| {
                                                        let spec = this.advanced_options[index]
                                                            .spec
                                                            .clone();
                                                        let input = cx.new(|cx| {
                                                            InputState::new(window, cx).placeholder(
                                                                spec.placeholder.clone(),
                                                            )
                                                        });
                                                        cx.observe(&input, |_, _, cx| cx.notify())
                                                            .detach();
                                                        this.advanced_options.insert(
                                                            index + 1,
                                                            AdvancedOption {
                                                                spec,
                                                                input,
                                                                enabled: false,
                                                            },
                                                        );
                                                        cx.notify();
                                                    },
                                                )),
                                        )
                                    })
                                }
                            }),
                    ),
            )
    }
    #[allow(clippy::too_many_arguments)]
    fn option(
        &self,
        id: &'static str,
        title: &'static str,
        description: &'static str,
        checked: bool,
        disabled: bool,
        update: fn(&mut Self, bool),
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        row().py_1().child(
            Checkbox::new(id)
                .label(title)
                .tooltip(description)
                .checked(checked)
                .disabled(disabled)
                .on_click(cx.listener(move |this, value, _, cx| {
                    update(this, *value);
                    cx.notify();
                })),
        )
    }
    fn shell_button(&self, shell: Shell, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        Button::new(if shell == Shell::Posix { "shell-posix" } else { "shell-powershell" })
            .small()
            .label(shell.label())
            .when(self.shell == shell, |b| b.primary())
            .on_click(cx.listener(move |this, _, _, cx| {
                this.shell = shell;
                cx.notify();
            }))
    }
    fn empty(
        &self,
        title: &str,
        description: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        column()
            .size_full()
            .items_center()
            .justify_center()
            .gap_4()
            .child(
                img(self.logo.clone())
                    .w(rems(7.))
                    .h(rems(9.))
                    .object_fit(gpui_kit::ObjectFit::Contain),
            )
            .child(heading(title, description))
            .child(
                Button::new("empty-open")
                    .icon(IconName::FolderOpen)
                    .label("Open report")
                    .on_click(cx.listener(|this, _, window, cx| this.choose(true, window, cx))),
            )
    }
    fn metric(title: &str, value: impl ToString, tint: u32) -> Div {
        panel()
            .flex_1()
            .border_t_2()
            .border_color(color(tint))
            .gap_2()
            .child(label(title.to_owned()))
            .child(div().text_3xl().text_color(color(tint)).child(number(value)))
    }
    fn overview(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let Some(data) = &self.data else {
            return self
                .empty(
                    "Your report workspace",
                    "Run a scan or open JSON, JSONL, or SARIF reports.",
                    cx,
                )
                .into_any_element();
        };
        let active = data.findings.iter().filter(|f| f.active()).count();
        let mut families: Vec<_> = data.families().into_iter().collect();
        families.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let max = families.first().map(|(_, n)| *n).unwrap_or(1).max(1);
        let target = data
            .metadata
            .first()
            .map(|m| text(m, &["target"]))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{} {} loaded",
                    number(data.sources.len()),
                    if data.sources.len() == 1 { "report" } else { "reports" }
                )
            });
        let completed = data.coverage.iter().filter(|r| r["scan"]["status"] == "completed").count();
        column()
            .id("overview-scroll")
            .size_full()
            .overflow_y_scroll()
            .p_5()
            .gap_5()
            .child(
                row().justify_between().child(heading("Scan overview", &target)).child(
                    Button::new("overview-findings")
                        .icon(IconName::ArrowRight)
                        .label("Explore findings")
                        .on_click(cx.listener(|this, _, _, cx| this.navigate(Tab::Findings, cx))),
                ),
            )
            .child(
                row()
                    .gap_4()
                    .child(Self::metric("TOTAL FINDINGS", data.findings.len(), BLUE))
                    .child(Self::metric("ACTIVE CREDENTIALS", active, RED))
                    .child(Self::metric("REPOSITORIES", data.coverage.len(), GREEN))
                    .child(Self::metric("MAPPED IDENTITIES", data.identities.len(), AMBER)),
            )
            .child(
                row()
                    .items_start()
                    .gap_5()
                    .child(
                        panel()
                            .flex_1()
                            .child(
                                row()
                                    .gap_2()
                                    .child(icon(IconName::ChartColumn).text_color(color(BLUE)))
                                    .child("TOP DETECTOR FAMILIES"),
                            )
                            .when(families.is_empty(), |view| {
                                view.child(label("No findings in this report."))
                            })
                            .children(families.into_iter().take(10).map(|(name, count)| {
                                column()
                                    .gap_2()
                                    .child(
                                        row()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w_0()
                                                    .text_sm()
                                                    .truncate()
                                                    .child(name),
                                            )
                                            .child(label(number(count))),
                                    )
                                    .child(
                                        div().h_1().bg(color(INSET)).child(
                                            div()
                                                .h_full()
                                                .w(relative(count as f32 / max as f32))
                                                .bg(color(BLUE)),
                                        ),
                                    )
                            })),
                    )
                    .child(
                        panel()
                            .w(rems(25.))
                            .child(
                                row()
                                    .gap_2()
                                    .child(icon(IconName::ShieldCheck).text_color(color(GREEN)))
                                    .child("COVERAGE & CONTEXT"),
                            )
                            .child(div().text_2xl().child(format!(
                                "{} / {}",
                                number(completed),
                                number(data.coverage.len())
                            )))
                            .child(label("repositories completed successfully"))
                            .child(
                                Button::new("overview-coverage")
                                    .ghost()
                                    .icon(IconName::Folders)
                                    .label("Inspect repository coverage")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.navigate(Tab::Coverage, cx)
                                    })),
                            )
                            .children(
                                data.metadata
                                    .iter()
                                    .take(1)
                                    .flat_map(|m| {
                                        [
                                            (
                                                "GENERATED",
                                                text(
                                                    m,
                                                    &[
                                                        "generated_at",
                                                        "scan_timestamp",
                                                        "scan_date",
                                                    ],
                                                ),
                                            ),
                                            ("KINGFISHER", text(m, &["kingfisher_version"])),
                                        ]
                                    })
                                    .map(|(key, value)| {
                                        column()
                                            .gap_1()
                                            .child(label(key))
                                            .child(selectable(key, value))
                                    }),
                            ),
                    ),
            )
            .into_any_element()
    }
    fn context_details(&self) -> Div {
        let Some(index) = self.selected else {
            return column();
        };
        let Some(data) = &self.data else {
            return column();
        };
        let mut view = column().gap_3();
        if self.tab == Tab::Access {
            let Some(record) = data.identities.get(index) else {
                return view;
            };
            view = view
                .child(Self::badge(&text(record, &["provider"]), BLUE))
                .child(
                    div().text_sm().child(text(&record["context"], &["identity_id", "account_id"])),
                )
                .child(label("PERMISSIONS BY SEVERITY"));
            for (key, title, tint) in [
                ("admin", "Admin", RED),
                ("privilege_escalation", "Privilege escalation", RED),
                ("risky", "Risky", AMBER),
                ("read_only", "Read only", GREEN),
            ] {
                let permissions = record["permissions_by_severity"][key].as_array();
                if let Some(permissions) = permissions.filter(|p| !p.is_empty()) {
                    view = view.child(
                        column().gap_1().child(Self::badge(title, tint)).children(
                            permissions
                                .iter()
                                .filter_map(|p| p.as_str())
                                .map(|p| div().text_sm().child(p.to_owned())),
                        ),
                    );
                }
            }
            view = view.child(label("REACHABLE RESOURCES"));
            for group in record["groups"].as_array().into_iter().flatten() {
                view = view.child(
                    column()
                        .gap_1()
                        .p_3()
                        .bg(color(INSET))
                        .children(
                            group["resources"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|p| p.as_str())
                                .map(|p| div().text_sm().child(p.to_owned())),
                        )
                        .child(label(
                            group["permissions"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|p| p.as_str())
                                .collect::<Vec<_>>()
                                .join(" · "),
                        )),
                );
            }
            let evidence = &record["provider_metadata"]["authorization_evidence"];
            for path in evidence["paths"].as_array().into_iter().flatten() {
                view = view
                    .child(label(format!("ACCESS PATH · {}", text(path, &["status"]))))
                    .children(path["hops"].as_array().into_iter().flatten().map(|hop| {
                        column()
                            .gap_1()
                            .p_3()
                            .bg(color(INSET))
                            .child(div().text_sm().child(text(hop, &["from"])))
                            .child(label(format!("↓ {}", text(hop, &["relationship"]))))
                            .child(div().text_sm().child(text(hop, &["to"])))
                    }));
            }
            view = view.children(
                evidence["limitations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| p.as_str())
                    .map(|p| label(p.to_owned()).text_color(color(AMBER))),
            );
        } else if self.tab == Tab::Coverage {
            let Some(record) = data.coverage.get(index) else {
                return view;
            };
            view = view.child(div().text_sm().child(text(record, &["repository", "key"])));
            for (key, title) in [("fetch", "FETCH"), ("scan", "SCAN")] {
                view = view.child(label(title)).child(Self::badge(
                    &text(&record[key], &["status"]),
                    if record[key]["status"] == "failed" { RED } else { BLUE },
                ));
                let error = text(&record[key], &["error"]);
                if !error.is_empty() {
                    view = view.child(div().text_sm().text_color(color(RED)).child(error));
                }
            }
            view = view
                .child(label("GIT SCOPE"))
                .child(div().text_sm().child(text(&record["git"], &["scope"])))
                .child(label(format!(
                    "{} findings · {} blobs scanned",
                    number(text(&record["stats"], &["findings"])),
                    number(text(&record["stats"], &["blobs_scanned"]))
                )));
        }
        view
    }
    fn inspector(&self, cx: &mut Context<Self>) -> Div {
        let selected = self.selected;
        let finding = if self.tab == Tab::Findings {
            selected.and_then(|i| self.data.as_ref()?.findings.get(i))
        } else {
            None
        };
        let title = finding.map(|f| f.rule.clone()).unwrap_or_else(|| {
            if selected.is_some() { "Selection details".into() } else { "Inspect a record".into() }
        });
        column()
            .relative()
            .w(rems(25.))
            .h_full()
            .flex_shrink_0()
            .border_l_1()
            .border_color(color(BORDER))
            .bg(color(PANEL))
            .child(
                row()
                    .p_4()
                    .justify_between()
                    .border_b_1()
                    .border_color(color(BORDER))
                    .child(label("INSPECTOR"))
                    .child(
                        Button::new("copy-detail")
                            .ghost()
                            .small()
                            .icon(IconName::Copy)
                            .label("Copy JSON")
                            .disabled(selected.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.copy(this.detail.clone(), "Record copied", cx)
                            })),
                    ),
            )
            .child(
                column()
                    .id("inspector-scroll")
                    .track_scroll(&self.inspector_scroll)
                    .flex_1()
                    .min_h_0()
                    .overflow_scroll()
                    .p_4()
                    .gap_3()
                    .child(selectable("detail-title", title))
                    .when_some(finding, |view, finding| {
                        view.child(selectable(
                            "detail-path",
                            format!("{}:{}", finding.path, number(finding.line)),
                        ))
                        .children(finding.source_links().into_iter().map(|(name, url)| {
                            Button::new(name)
                                .ghost()
                                .small()
                                .label(name)
                                .tooltip(url.clone())
                                .on_click(move |_, _, cx| cx.open_url(&url))
                        }))
                        .child(row().gap_2().child(Self::badge(
                            &finding.status,
                            if finding.active() { RED } else { MUTED },
                        )))
                        .child(label("MATCHED CONTENT"))
                        .child(
                            div()
                                .id("snippet-selection")
                                .test_support()
                                .p_3()
                                .bg(color(INSET))
                                .text_sm()
                                .font_family(cx.theme().mono_font_family.clone())
                                .child(selectable("detail-snippet", &finding.snippet)),
                        )
                        .child(
                            Button::new("copy-snippet")
                                .ghost()
                                .small()
                                .icon(IconName::Copy)
                                .label("Copy snippet")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    if let Some(f) = this
                                        .selected
                                        .and_then(|i| this.data.as_ref()?.findings.get(i))
                                    {
                                        this.copy(f.snippet.clone(), "Snippet copied", cx);
                                    }
                                })),
                        )
                    })
                    .when_some(finding, |view, finding| {
                        view.child(self.finding_details(finding, cx))
                    })
                    .child(self.context_details())
                    .when(selected.is_some(), |view| {
                        view.child(
                            Button::new("raw-evidence")
                                .ghost()
                                .small()
                                .icon(if self.raw_open {
                                    IconName::ChevronDown
                                } else {
                                    IconName::ChevronRight
                                })
                                .label("Raw evidence")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.raw_open = !this.raw_open;
                                    cx.notify();
                                })),
                        )
                    })
                    .when(self.raw_open || (selected.is_some() && finding.is_none()), |view| {
                        view.child(
                            div()
                                .text_xs()
                                .font_family(cx.theme().mono_font_family.clone())
                                .child(selectable("detail-json", &self.detail)),
                        )
                    }),
            )
            .child(
                div()
                    .absolute()
                    .inset_0()
                    .child(Scrollbar::new(&self.inspector_scroll).mode(ScrollbarMode::Always)),
            )
    }
    fn finding_details(&self, finding: &super::report::Finding, cx: &mut Context<Self>) -> Div {
        let mut view = column().gap_3().child(label("SOURCE & TRIAGE"));
        for (name, value) in [
            ("Repository", finding.field("Repository")),
            (
                "Author",
                format!(
                    "{} {}",
                    text(&finding.raw["finding"]["git_metadata"]["commit"]["author"], &["name"]),
                    text(&finding.raw["finding"]["git_metadata"]["commit"]["author"], &["email"])
                )
                .trim()
                .to_owned(),
            ),
            (
                "Committer",
                format!(
                    "{} {}",
                    text(&finding.raw["finding"]["git_metadata"]["commit"]["committer"], &["name"]),
                    text(
                        &finding.raw["finding"]["git_metadata"]["commit"]["committer"],
                        &["email"]
                    )
                )
                .trim()
                .to_owned(),
            ),
            ("Commit date", finding.field("Commit date")),
            ("Commit", finding.field("Commit")),
            ("Entropy", finding.field("entropy")),
            ("Language", finding.field("language")),
            ("Encoding", finding.field("encoding")),
            ("Fingerprint", finding.fingerprint.clone()),
            ("Description", text(&finding.raw["rule"], &["description"])),
        ] {
            if !value.is_empty() {
                view =
                    view.child(column().gap_1().child(label(name)).child(selectable(name, value)));
            }
        }
        view = view.child(label("CREDENTIAL ACTIONS")).child(
            row()
                .gap_2()
                .child(self.shell_button(Shell::Posix, cx))
                .child(self.shell_button(Shell::PowerShell, cx)),
        );
        for (key, title) in [
            ("validate_command", "Validate"),
            ("revoke_command", "Revoke"),
            ("blast_radius_command", "Blast radius"),
        ] {
            let command = finding.field(key);
            if command.is_empty() {
                view = view.child(label(format!(
                    "{title}: unavailable in this report (redacted or unsupported)."
                )));
            } else {
                let converted = report_command_preview(&command, self.shell);
                let can_copy = converted.is_ok();
                let command = converted
                    .unwrap_or_else(|_| format!("Original report command (Bash/zsh):\n{command}"));
                let copied = command.clone();
                view = view.child(
                    column()
                        .gap_2()
                        .p_3()
                        .bg(color(INSET))
                        .child(
                            row().justify_between().child(label(title)).child(
                                Button::new(key)
                                    .disabled(!can_copy)
                                    .small()
                                    .ghost()
                                    .icon(IconName::Copy)
                                    .label("Copy command")
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.copy(copied.clone(), "Command copied", cx)
                                    })),
                            ),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family(cx.theme().mono_font_family.clone())
                                .child(selectable(key, command)),
                        ),
                );
            }
        }
        view
    }
    fn finding_filters(&self, cx: &mut Context<Self>) -> Div {
        let entity = cx.entity().downgrade();
        let available: Vec<_> = self
            .filters
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.visible_filters.contains(index))
            .map(|(index, (name, _))| (index, name.clone()))
            .collect();
        column()
            .gap_2()
            .child(
                row()
                    .gap_2()
                    .child(
                        Button::new("finding-filters")
                            .small()
                            .ghost()
                            .icon(IconName::Plus)
                            .label("Add filter")
                            .disabled(available.is_empty())
                            .dropdown_menu(move |mut menu, _, _| {
                                for (index, name) in &available {
                                    let index = *index;
                                    let entity = entity.clone();
                                    menu = menu.item(PopupMenuItem::new(name.clone()).on_click(
                                        move |_, _, cx| {
                                            let _ = entity.update(cx, |this, cx| {
                                                if !this.visible_filters.contains(&index) {
                                                    this.visible_filters.push(index);
                                                }
                                                cx.notify();
                                            });
                                        },
                                    ));
                                }
                                menu
                            }),
                    )
                    .when(
                        !self.visible_filters.is_empty()
                            || !self.search.read(cx).value().is_empty()
                            || self.active_only,
                        |view| {
                            view.child(
                                Button::new("reset-filters")
                                    .ghost()
                                    .small()
                                    .label("Clear all")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        for (_, input) in &this.filters {
                                            input.update(cx, |state, cx| {
                                                state.set_value("", window, cx)
                                            });
                                        }
                                        this.visible_filters.clear();
                                        this.search.update(cx, |state, cx| {
                                            state.set_value("", window, cx)
                                        });
                                        this.active_only = false;
                                        this.refilter(cx);
                                        cx.notify();
                                    })),
                            )
                        },
                    ),
            )
            .when(!self.visible_filters.is_empty(), |view| {
                view.child(
                    column()
                        .id("filter-scroll")
                        .max_h(rems(12.))
                        .overflow_y_scroll()
                        .gap_1()
                        .children(self.visible_filters.iter().map(|index| {
                            let index = *index;
                            let (name, input) = &self.filters[index];
                            let value = input.read(cx).value().to_string();
                            let condition =
                                row().gap_2().child(div().w(rems(8.)).child(label(name.clone())));
                            let condition = if index == 0 {
                                let mut values: Vec<_> = self
                                    .data
                                    .as_ref()
                                    .map(|data| {
                                        data.findings
                                            .iter()
                                            .map(|finding| finding.status.clone())
                                            .filter(|v| !v.is_empty())
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                values.sort();
                                values.dedup();
                                let input = input.clone();
                                condition.child(
                                    Button::new(("filter-choice", index))
                                        .small()
                                        .label(if value.is_empty() {
                                            "Any".into()
                                        } else {
                                            value.clone()
                                        })
                                        .icon(IconName::ChevronDown)
                                        .dropdown_menu(move |mut menu, _, _| {
                                            for choice in
                                                std::iter::once(String::new()).chain(values.clone())
                                            {
                                                let input = input.clone();
                                                menu = menu.item(
                                                    PopupMenuItem::new(if choice.is_empty() {
                                                        "Any".into()
                                                    } else {
                                                        choice.clone()
                                                    })
                                                    .checked(value == choice)
                                                    .on_click(move |_, window, cx| {
                                                        input.update(cx, |state, cx| {
                                                            state.set_value(
                                                                choice.clone(),
                                                                window,
                                                                cx,
                                                            )
                                                        })
                                                    }),
                                                );
                                            }
                                            menu
                                        }),
                                )
                            } else {
                                condition.child(
                                    div().flex_1().min_w_0().child(
                                        Input::new(input)
                                            .id(("finding-filter", index))
                                            .small()
                                            .aria_label(name.clone()),
                                    ),
                                )
                            };
                            condition.child(div().flex_1()).child(
                                Button::new(("remove-filter", index))
                                    .small()
                                    .ghost()
                                    .icon(IconName::X)
                                    .accessibility_label("Remove filter")
                                    .tooltip("Remove filter")
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.filters[index].1.update(cx, |state, cx| {
                                            state.set_value("", window, cx)
                                        });
                                        this.visible_filters.retain(|i| *i != index);
                                        this.refilter(cx);
                                        cx.notify();
                                    })),
                            )
                        }))
                        .child(label("Match every condition · Dates include both endpoints")),
                )
            })
    }
    fn badge(value: &str, tint: u32) -> Div {
        div()
            .px_2()
            .py_1()
            .rounded_sm()
            .bg(color(tint).opacity(0.12))
            .text_color(color(tint))
            .text_xs()
            .child(selectable(
                format!("badge-{value}"),
                if value.is_empty() { "Unknown" } else { value },
            ))
    }
    fn finding_row(&self, index: usize, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let f = &self.data.as_ref().unwrap().findings[index];
        gpui_kit::base::Button::new(("finding", index))
            .w_full()
            .accessibility_label(format!(
                "{} · {}:{} · {}",
                f.rule,
                f.path,
                number(f.line),
                f.status
            ))
            .flex()
            .items_center()
            .justify_start()
            .h(rems(2.5))
            .px_2()
            .border_b_1()
            .border_color(color(BORDER).opacity(0.45))
            .bg(if self.selected == Some(index) { color(BLUE).opacity(0.18) } else { color(BG) })
            .border_l_2()
            .border_color(if self.selected == Some(index) {
                color(BLUE)
            } else {
                color(BORDER).opacity(0.45)
            })
            .hover(|s| s.bg(color(PANEL)))
            .cursor_pointer()
            .children(self.columns.iter().map(|(column, width)| {
                let column = *column;
                div()
                    .w(px(*width))
                    .min_w_0()
                    .flex_shrink_0()
                    .px_2()
                    .text_sm()
                    .truncate()
                    .text_color(color(if column == FindingColumn::Status && f.active() {
                        RED
                    } else {
                        TEXT
                    }))
                    .child(column.value(f))
            }))
            .on_click(cx.listener(move |this, _, window, cx| {
                window.focus(&this.findings_focus, cx);
                this.select_finding(index, cx);
            }))
    }
    fn select_finding(&mut self, index: usize, cx: &mut Context<Self>) {
        self.selected = Some(index);
        self.detail =
            serde_json::to_string_pretty(&self.data.as_ref().unwrap().findings[index].raw)
                .unwrap_or_default();
        cx.notify();
    }
    fn move_finding(&mut self, forward: bool, cx: &mut Context<Self>) {
        if self.filtered.is_empty() {
            return;
        }
        let position = self
            .selected
            .and_then(|selected| self.filtered.iter().position(|index| *index == selected));
        let next = match position {
            Some(position) if forward => (position + 1).min(self.filtered.len() - 1),
            Some(position) => position.saturating_sub(1),
            None => 0,
        };
        self.select_finding(self.filtered[next], cx);
        self.findings_scroll.scroll_to_item(next, gpui_kit::ScrollStrategy::Nearest);
    }

    fn column_picker(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let entity = cx.entity().downgrade();
        let columns = self.columns.clone();
        Button::new("finding-columns").small().ghost().label("Columns").dropdown_menu(
            move |mut menu, _, _| {
                for column in FindingColumn::ALL {
                    let checked = columns.iter().any(|(c, _)| *c == column);
                    let entity = entity.clone();
                    menu = menu.item(PopupMenuItem::new(column.label()).checked(checked).on_click(
                        move |_, _, cx| {
                            let _ = entity.update(cx, |this, cx| {
                                if this.columns.iter().any(|(c, _)| *c == column) {
                                    if this.columns.len() > 1 {
                                        this.columns.retain(|(c, _)| *c != column);
                                    }
                                } else {
                                    this.columns.push((column, column.width()));
                                }
                                cx.notify();
                            });
                        },
                    ));
                }
                menu
            },
        )
    }
    fn findings(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        if self.data.is_none() {
            return self
                .empty("Findings", "Open a report to inspect its findings.", cx)
                .into_any_element();
        }
        let indices = self.filtered.clone();
        let count = indices.len();
        let header = row()
            .h(px(36.))
            .flex_shrink_0()
            .px_2()
            .py_1()
            .bg(color(PANEL))
            .border_b_1()
            .border_color(color(BORDER))
            .children(self.columns.iter().copied().enumerate().map(|(index, (column, width))| {
                let descending = self
                    .finding_sort
                    .filter(|(selected, _)| *selected == column)
                    .map(|(_, descending)| descending);
                row()
                    .w(px(width))
                    .min_w_0()
                    .flex_shrink_0()
                    .child(
                        Button::new(("sort-finding", index))
                            .ghost()
                            .small()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .label(format!(
                                "{}{}",
                                column.label(),
                                match descending {
                                    Some(true) => " ↓",
                                    Some(false) => " ↑",
                                    None => "",
                                }
                            ))
                            .tooltip(format!("Sort by {}", column.label()))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.finding_sort = Some((column, !descending.unwrap_or(true)));
                                this.refilter(cx);
                                this.findings_scroll
                                    .scroll_to_item(0, gpui_kit::ScrollStrategy::Top);
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .id(("resize-column", index))
                            .test_support()
                            .flex_shrink_0()
                            .w(px(6.))
                            .h(px(28.))
                            .cursor_col_resize()
                            .bg(color(BORDER))
                            .on_mouse_down(
                                gpui_kit::MouseButton::Left,
                                cx.listener(
                                    move |this, event: &gpui_kit::MouseDownEvent, _, cx| {
                                        this.resizing = Some((index, event.position.x, width));
                                        cx.stop_propagation();
                                    },
                                ),
                            ),
                    )
            }));
        let navigation = column()
            .id("finding-navigation")
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .track_focus(&self.findings_focus)
            .on_key_down(cx.listener(|this, event: &gpui_kit::KeyDownEvent, _, cx| {
                match event.keystroke.key.as_str() {
                    "up" => this.move_finding(false, cx),
                    "down" => this.move_finding(true, cx),
                    _ => return,
                }
                cx.stop_propagation();
            }))
            .child(
                uniform_list(
                    "finding-list",
                    indices.len(),
                    cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                        range.map(|row| this.finding_row(indices[row], cx)).collect()
                    }),
                )
                .track_scroll(&self.findings_scroll)
                .size_full(),
            );
        row()
            .size_full()
            .items_start()
            .on_mouse_move(cx.listener(|this, event: &gpui_kit::MouseMoveEvent, _, cx| {
                if let Some((index, start, width)) = this.resizing {
                    this.columns[index].1 =
                        (width + f32::from(event.position.x - start)).clamp(64., 1200.);
                    cx.notify();
                }
            }))
            .on_mouse_up(
                gpui_kit::MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.resizing = None;
                    cx.notify();
                }),
            )
            .on_mouse_up_out(
                gpui_kit::MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.resizing = None;
                    cx.notify();
                }),
            )
            .child(
                column()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(
                        column()
                            .p_4()
                            .gap_3()
                            .border_b_1()
                            .border_color(color(BORDER))
                            .child(
                                row()
                                    .justify_between()
                                    .child(heading(
                                        "Findings",
                                        &format!("{} matching records", number(count)),
                                    ))
                                    .child(
                                        Button::new("export-filtered")
                                            .ghost()
                                            .small()
                                            .icon(IconName::Download)
                                            .label("Export filtered")
                                            .on_click(
                                                cx.listener(|this, _, _, cx| this.save(true, cx)),
                                            ),
                                    ),
                            )
                            .child(
                                Input::new(&self.search)
                                    .id("finding-search")
                                    .aria_label("Search findings"),
                            )
                            .child(self.finding_filters(cx))
                            .child(row().child(self.column_picker(cx)))
                            .child(
                                row()
                                    .gap_5()
                                    .child(
                                        Checkbox::new("active-only")
                                            .label("Active only")
                                            .checked(self.active_only)
                                            .on_click(cx.listener(|this, value, _, cx| {
                                                this.active_only = *value;
                                                this.refilter(cx);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Checkbox::new("unique")
                                            .label("Unique secrets")
                                            .checked(self.unique)
                                            .on_click(cx.listener(|this, value, _, cx| {
                                                this.unique = *value;
                                                this.refilter(cx);
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .overflow_hidden()
                            .child(
                                div()
                                    .id("findings-horizontal")
                                    .test_support()
                                    .size_full()
                                    .overflow_x_scroll()
                                    .track_scroll(&self.horizontal_scroll)
                                    .child(
                                        column()
                                            .w(px(self
                                                .columns
                                                .iter()
                                                .map(|(_, width)| width)
                                                .sum::<f32>()
                                                + 20.))
                                            .h_full()
                                            .child(header)
                                            .when(count == 0, |view| {
                                                view.child(
                                                    div()
                                                        .p_5()
                                                        .text_color(color(MUTED))
                                                        .child("No findings match these filters."),
                                                )
                                            })
                                            .child(navigation),
                                    ),
                            )
                            .child(
                                div().absolute().top(px(36.)).bottom_0().left_0().right_0().child(
                                    Scrollbar::vertical(&self.findings_scroll)
                                        .viewport_from_layout()
                                        .mode(ScrollbarMode::Always),
                                ),
                            )
                            .child(
                                div().absolute().inset_0().child(
                                    Scrollbar::horizontal(&self.horizontal_scroll)
                                        .viewport_from_layout()
                                        .mode(ScrollbarMode::Always),
                                ),
                            ),
                    ),
            )
            .child(self.inspector(cx))
            .into_any_element()
    }
    fn records(&self, access: bool, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let Some(data) = &self.data else {
            return self
                .empty("Report details", "Open a report to inspect coverage and blast radius.", cx)
                .into_any_element();
        };
        let count = if access { data.identities.len() } else { data.coverage.len() };
        row().size_full().items_start().child(column().flex_1().min_w_0().h_full()
            .child(div().p_5().border_b_1().border_color(color(BORDER)).child(heading(if access{"Blast radius"}else{"Repository coverage"},
                if access{"Select an identity to inspect permissions, resources, and authorization evidence."}else{"Inspect scan and fetch outcomes, errors, and Git scope for every repository."})))
            .when(count==0,|v|v.child(div().p_5().text_color(color(MUTED)).child(if access{"This report contains no mapped identities. Enable validation and blast-radius mapping for your next scan."}else{"This report contains no repository audit data."})))
            .child(uniform_list(if access{"identity-list"}else{"coverage-list"},count,cx.processor(move|this,range: std::ops::Range<usize>,_,cx|{
                range.map(|index|{
                    let data=this.data.as_ref().unwrap();let record=if access{&data.identities[index]}else{&data.coverage[index]};
                    let title=if access{text(&record["context"],&["identity_id","account_id"])}else{text(record,&["repository","key"])};
                    let subtitle=if access{text(record,&["provider","account"])}else{format!("Fetch: {} · Scan: {} · {} findings",text(&record["fetch"],&["status"]),text(&record["scan"],&["status"]),number(record["stats"]["findings"].as_u64().unwrap_or(0)))};
                    let failed=record["scan"]["status"]=="failed"||record["fetch"]["status"]=="failed";
                    gpui_kit::base::Button::new(("record",index)).accessibility_label(format!("{title} · {subtitle}"))
                        .flex().items_center().justify_start().h(rems(4.5)).px_4().gap_3().border_b_1().border_color(color(BORDER)).cursor_pointer()
                        .bg(color(if this.selected==Some(index){PANEL}else{BG})).hover(|s|s.bg(color(PANEL)))
                        .child(icon(if access{IconName::Network}else{IconName::FolderGit2}).text_color(color(if failed{RED}else{AMBER})))
                        .child(column().flex_1().min_w_0().gap_1().child(div().truncate().child(if title.is_empty(){"Unnamed identity".into()}else{title}))
                            .child(div().truncate().text_xs().text_color(color(MUTED)).child(subtitle)))
                        .child(icon(IconName::ChevronRight).text_color(color(MUTED)))
                        .on_click(cx.listener(move|this,_,_,cx|{this.selected=Some(index);let data=this.data.as_ref().unwrap();
                            this.detail=serde_json::to_string_pretty(if access{&data.identities[index]}else{&data.coverage[index]}).unwrap_or_default();cx.notify();}))
                }).collect()
            })).flex_1().min_h_0())).child(self.inspector(cx)).into_any_element()
    }
    fn activity_view(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let lines: Arc<Vec<String>> = Arc::new(self.activity.lines().map(str::to_owned).collect());
        let count = lines.len();
        let mono = cx.theme().mono_font_family.clone();
        column()
            .size_full()
            .p_5()
            .gap_4()
            .child(
                row().justify_between().child(heading("Activity log", &self.status)).child(
                    row()
                        .gap_2()
                        .child(
                            Checkbox::new("follow-log")
                                .label("Follow")
                                .checked(self.follow_log)
                                .on_click(cx.listener(|this, value, _, cx| {
                                    this.follow_log = *value;
                                    cx.notify();
                                })),
                        )
                        .child(
                            Button::new("copy-log")
                                .icon(IconName::Copy)
                                .label("Copy log")
                                .disabled(self.activity.is_empty())
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.copy(this.activity.clone(), "Activity log copied", cx)
                                })),
                        )
                        .child(
                            Button::new("cancel")
                                .icon(IconName::Square)
                                .label("Cancel scan")
                                .disabled(self.scan.is_none())
                                .on_click(cx.listener(|this, _, _, cx| this.cancel(cx))),
                        ),
                ),
            )
            .when_some(self.scan.as_ref(), |view, scan| {
                let bytes = scan.progress["bytes"].as_u64().unwrap_or(0) as f64;
                let phase = scan.progress["phase"].as_str().unwrap_or("Preparing scan");
                let validating = scan.progress["kind"] == "validation";
                let scanning = scan.progress["kind"] == "scan";
                let tint = if validating { AMBER } else { BLUE };
                let completed = scan.progress["completed"].as_u64().unwrap_or(0);
                let total = scan.progress["total"].as_u64().unwrap_or(0);
                view.child(
                    panel()
                        .border_color(color(tint))
                        .bg(color(tint).opacity(0.08))
                        .child(
                            row()
                                .gap_3()
                                .child(
                                    icon(if validating {
                                        IconName::ShieldCheck
                                    } else {
                                        IconName::Scan
                                    })
                                    .text_color(color(tint)),
                                )
                                .child(
                                    div()
                                        .text_lg()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .child(phase.to_owned()),
                                ),
                        )
                        .child(label(if validating {
                            "Scanning complete. Checking credentials with their providers."
                        } else if scanning {
                            "Reading files and matching secret detectors."
                        } else {
                            "Working through your scan."
                        }))
                        .when(validating, |view| {
                            view.child(div().text_lg().child(format!(
                                "{} / {} credentials checked",
                                number(completed),
                                number(total)
                            )))
                            .child(
                                div().w_full().h(px(6.)).rounded_full().bg(color(BORDER)).child(
                                    div().h_full().rounded_full().bg(color(AMBER)).w(relative(
                                        if total == 0 {
                                            0.
                                        } else {
                                            (completed as f32 / total as f32).min(1.)
                                        },
                                    )),
                                ),
                            )
                        }),
                )
                .child(
                    row()
                        .gap_3()
                        .child(Self::metric("GB SCANNED", format!("{:.3}", bytes / 1e9), BLUE))
                        .child(Self::metric(
                            "BLOBS PROCESSED",
                            number(scan.progress["blobs"].as_u64().unwrap_or(0)),
                            AMBER,
                        ))
                        .child(Self::metric(
                            if validating
                                || phase == "Mapping credential access"
                                || phase == "Writing report"
                            {
                                "FINAL SCAN MB / SECOND"
                            } else {
                                "SCAN MB / SECOND"
                            },
                            format!("{:.1}", scan_rate(&scan.progress)),
                            GREEN,
                        )),
                )
            })
            .when_some(self.error.clone(), |v, error| {
                v.child(
                    row()
                        .gap_3()
                        .p_3()
                        .bg(color(RED).opacity(0.12))
                        .border_1()
                        .border_color(color(RED).opacity(0.4))
                        .child(icon(IconName::CircleAlert).text_color(color(RED)))
                        .child(div().text_color(color(RED)).child(error)),
                )
            })
            .child(
                column()
                    .flex_1()
                    .min_h_0()
                    .bg(color(INSET))
                    .border_1()
                    .border_color(color(BORDER))
                    .p_3()
                    .when(count == 0, |v| {
                        v.child(label(
                            "Scan progress, errors, and report loading details appear here.",
                        ))
                    })
                    .child(
                        uniform_list("activity-lines", count, move |range, _, _| {
                            range
                                .map(|i| {
                                    row()
                                        .h(rems(1.5))
                                        .gap_3()
                                        .child(
                                            div()
                                                .w(rems(3.))
                                                .text_color(color(MUTED))
                                                .child(number(i + 1)),
                                        )
                                        .child(
                                            div()
                                                .font_family(mono.clone())
                                                .text_xs()
                                                .child(lines[i].clone()),
                                        )
                                })
                                .collect()
                        })
                        .track_scroll(&self.log_scroll)
                        .flex_1()
                        .min_h_0(),
                    ),
            )
    }
}

impl Render for Desktop {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.tab {
            Tab::Scan => self.scan_view(cx).into_any_element(),
            Tab::Overview => self.overview(cx).into_any_element(),
            Tab::Findings => self.findings(cx).into_any_element(),
            Tab::Coverage => self.records(false, cx).into_any_element(),
            Tab::Access => self.records(true, cx).into_any_element(),
            Tab::Activity => self.activity_view(cx).into_any_element(),
        };
        column()
            .size_full()
            .bg(color(BG))
            .text_color(color(TEXT))
            .text_sm()
            .child(
                row()
                    .px_5()
                    .py_3()
                    .gap_3()
                    .border_b_1()
                    .border_color(color(BORDER))
                    .child(img(self.logo.clone()).w(px(33.)).h(px(44.)))
                    .child(
                        column()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(FontWeight::BOLD)
                                    .child("MongoDB Kingfisher"),
                            )
                            .child(label(
                                "Find and Validate leaked secrets. Map Blast Radius. Revoke Fast",
                            )),
                    )
                    .child({
                        let entity = cx.entity().downgrade();
                        let current = self.theme_mode;
                        Button::new("theme-mode")
                            .label(match current {
                                None => "Theme: System",
                                Some(ThemeMode::Light) => "Theme: Light",
                                _ => "Theme: Dark",
                            })
                            .dropdown_menu(move |mut menu, _, _| {
                                for (label, mode) in [
                                    ("System", None),
                                    ("Light", Some(ThemeMode::Light)),
                                    ("Dark", Some(ThemeMode::Dark)),
                                ] {
                                    let entity = entity.clone();
                                    menu = menu.item(
                                        PopupMenuItem::new(label)
                                            .checked(current == mode)
                                            .on_click(move |_, window, cx| {
                                                let _ = entity.update(cx, |this, cx| {
                                                    this.theme_mode = mode;
                                                    cx.set_window_appearance(mode.map(|m| {
                                                        if m.is_dark() {
                                                            gpui_kit::WindowAppearance::Dark
                                                        } else {
                                                            gpui_kit::WindowAppearance::Light
                                                        }
                                                    }));
                                                    if let Some(mode) = mode {
                                                        Theme::change(mode, Some(window), cx);
                                                    } else {
                                                        Theme::sync_system_appearance(
                                                            Some(window),
                                                            cx,
                                                        );
                                                    }
                                                    configure_theme(cx);
                                                    cx.notify();
                                                });
                                            }),
                                    );
                                }
                                menu
                            })
                    })
                    .child(
                        Button::new("open-reports")
                            .icon(IconName::FolderOpen)
                            .label("Open report")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.choose(true, window, cx)),
                            ),
                    )
                    .child(
                        Button::new("export-report")
                            .icon(IconName::Download)
                            .label("Export JSON")
                            .disabled(self.data.is_none())
                            .on_click(cx.listener(|this, _, _, cx| this.save(false, cx))),
                    )
                    .child(
                        Button::new("browser-report")
                            .icon(IconName::Globe)
                            .label("Local Web Viewer")
                            .disabled(self.data.is_none())
                            .on_click(cx.listener(|this, _, _, cx| this.browser(cx))),
                    ),
            )
            .when(!self.reports.is_empty(), |view| view.child(self.report_tabs(cx)))
            .child(
                row().px_5().gap_1().py_2().border_b_1().border_color(color(BORDER)).children(
                    [
                        Tab::Scan,
                        Tab::Overview,
                        Tab::Findings,
                        Tab::Coverage,
                        Tab::Access,
                        Tab::Activity,
                    ]
                    .into_iter()
                    .map(|tab| {
                        Button::new(tab.label())
                            .icon(tab.icon())
                            .label(tab.label())
                            .ghost()
                            .when(self.tab == tab, |button| button.primary())
                            .on_click(cx.listener(move |this, _, _, cx| this.navigate(tab, cx)))
                    }),
                ),
            )
            .child(div().flex_1().min_h_0().overflow_hidden().child(content))
            .child(
                row()
                    .h(px(34.))
                    .px_4()
                    .gap_3()
                    .bg(color(INSET))
                    .border_t_1()
                    .border_color(color(BORDER))
                    .child(div().w(px(6.)).h(px(6.)).rounded_full().bg(color(
                        if self.error.is_some() {
                            RED
                        } else if self.scan.is_some() {
                            AMBER
                        } else {
                            GREEN
                        },
                    )))
                    .child(label(if self.loading {
                        "Loading report…".to_owned()
                    } else {
                        self.status.clone()
                    }))
                    .child(div().flex_1())
                    .child(label(self.notice.clone()))
                    .child(
                        Button::new("show-activity")
                            .xsmall()
                            .ghost()
                            .icon(IconName::Terminal)
                            .label("Activity")
                            .on_click(
                                cx.listener(|this, _, _, cx| this.navigate(Tab::Activity, cx)),
                            ),
                    ),
            )
    }
}

fn configure_theme(cx: &mut App) {
    LIGHT_PALETTE.set(!cx.theme().is_dark());
    let theme = Theme::global_mut(cx);
    theme.background = color(BG);
    theme.foreground = color(TEXT);
    theme.border = color(BORDER);
    theme.input = color(BORDER);
    theme.muted = color(PANEL);
    theme.muted_foreground = color(MUTED);
    theme.primary = color(BLUE);
    theme.primary_foreground = color(BG);
    theme.secondary = color(PANEL);
    theme.secondary_foreground = color(TEXT);
    theme.popover = color(PANEL);
    theme.popover_foreground = color(TEXT);
    theme.radius = px(6.);
    theme.radius_lg = px(8.);
    theme.button = color(PANEL);
    theme.button_foreground = color(TEXT);
    theme.button_hover = color(BORDER);
    theme.button_active = color(BG);
    theme.button_primary = color(BLUE);
    theme.button_primary_foreground = color(BG);
    theme.button_primary_hover = color(0x8abaff);
    theme.button_primary_active = color(0xc6984f);
    theme.primary_hover = color(0x8abaff);
    theme.primary_active = color(0xc6984f);
    theme.accent = color(BORDER);
    theme.accent_foreground = color(TEXT);
    theme.ring = color(AMBER);
    theme.selection = color(BLUE).opacity(0.3);
    theme.font_size = px(14.);
    theme.tokens = theme.colors.into();
    Theme::sync_base(cx);
}

/// Launch on the OS main thread, before creating the CLI's Tokio runtime.
pub fn run(
    initial: Option<OsString>,
    report: Option<PathBuf>,
    globals: Vec<(String, String)>,
) -> anyhow::Result<()> {
    let executable = std::env::current_exe()?;
    gpui_kit::application().with_assets(super::assets::Assets).run(move |cx| {
        gpui_kit::init(cx);
        cx.set_app_identity(super::branding::APP_ID, "Kingfisher");
        if let Err(error) = super::branding::initialize(&executable) {
            eprintln!("Could not set the Kingfisher desktop icon: {error:#}");
        }
        Theme::sync_system_appearance(None, cx);
        configure_theme(cx);
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.bind_keys([KeyBinding::new("secondary-q", Quit, None)]);
        cx.set_menus(vec![Menu {
            name: "Kingfisher".into(),
            items: vec![MenuItem::action("Quit Kingfisher", Quit)],
            disabled: false,
        }]);
        cx.open_window(
            WindowOptions {
                app_id: Some(super::branding::APP_ID.into()),
                icon: Some(super::branding::window_icon()),
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1280.), px(850.)),
                    cx,
                ))),
                window_min_size: Some(size(px(1000.), px(680.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Kingfisher".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            move |window, cx| {
                let view = cx.new(|cx| {
                    let mut desktop = Desktop::new(executable, initial, window, cx);
                    for (flag, value) in globals {
                        if flag == "load-builtins" {
                            desktop.builtins = value != "false";
                            continue;
                        }
                        if flag == "rules-path" {
                            desktop.rule_paths.push(PathBuf::from(value));
                            continue;
                        }
                        if let Some(index) =
                            desktop.advanced_options.iter().position(|o| o.spec.flag == flag)
                        {
                            let option = &desktop.advanced_options[index];
                            if option.spec.repeatable && !option.input.read(cx).value().is_empty() {
                                let spec = option.spec.clone();
                                let input = cx.new(|cx| {
                                    InputState::new(window, cx)
                                        .placeholder(spec.placeholder.clone())
                                });
                                input.update(cx, |state, cx| state.set_value(value, window, cx));
                                cx.observe(&input, |_, _, cx| cx.notify()).detach();
                                desktop.advanced_options.push(AdvancedOption {
                                    spec,
                                    input,
                                    enabled: false,
                                });
                            } else {
                                desktop.advanced_options[index].enabled = value == "true";
                                desktop.advanced_options[index]
                                    .input
                                    .update(cx, |state, cx| state.set_value(value, window, cx));
                            }
                        }
                    }
                    desktop
                });
                if let Some(path) = report {
                    view.update(cx, |this, cx| this.load(vec![path], None, cx));
                }
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("open Kingfisher window");
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.activate(true);
    });
    Ok(())
}

#[cfg(all(test, feature = "gui-tests"))]
mod tests {
    use super::*;
    use gpui_kit::{TestAppContext, test::TestWindowExt};

    #[gpui_kit::test]
    async fn overlapping_report_loads_keep_each_file_in_its_own_tab(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let directory = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                let path = directory.path().join(format!("report-{index}.json"));
                std::fs::write(&path, include_bytes!("../../docs/viewer/sample-report.json"))
                    .unwrap();
                path
            })
            .collect();
        let missing = directory.path().join("missing.json");
        let mut desktop = None;
        let _handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| Desktop::new(PathBuf::from("kingfisher"), None, window, cx));
            view.update(cx, |view, cx| {
                view.load(vec![paths[0].clone(), missing, paths[1].clone()], None, cx);
                view.load(vec![paths[2].clone()], None, cx);
            });
            desktop = Some(view.clone());
            Root::new(view, window, cx)
        });
        let desktop = desktop.unwrap();
        cx.condition(&desktop, |view, _| !view.loading).await;
        cx.update(|cx| {
            let view = desktop.read(cx);
            assert_eq!(view.reports.len(), 3);
            assert_eq!(view.pending_loads, 0);
            assert!(view.error.is_some());
            for path in paths {
                assert!(
                    view.reports
                        .iter()
                        .any(|tab| tab.state.data.as_ref().unwrap().sources == vec![path.clone()])
                );
            }
        });
    }

    #[gpui_kit::test]
    fn report_tabs_preserve_state_and_release_only_closed_reports(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let storage = Arc::new(Report::new().unwrap());
        let temporary_path = storage.directory.path().to_owned();
        let sample = || {
            let mut report = ReportData::default();
            report.read_bytes(include_bytes!("../../docs/viewer/sample-report.json")).unwrap();
            report
        };
        let mut desktop = None;
        let handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| {
                let mut view = Desktop::new(PathBuf::from("kingfisher"), None, window, cx);
                view.add_report(sample(), Some(storage.clone()), window, cx);
                view.tab = Tab::Findings;
                let rule = view.data.as_ref().unwrap().findings[0].rule.clone();
                view.search.update(cx, |state, cx| state.set_value(rule.clone(), window, cx));
                view.filters[1].1.update(cx, |state, cx| state.set_value(rule, window, cx));
                view.visible_filters = vec![1];
                view.unique = false;
                view.raw_open = true;
                view.finding_sort = Some((FindingColumn::Line, true));
                view.columns[0].1 = 333.;
                view.refilter(cx);
                view.select_finding(view.filtered[0], cx);
                view.navigate(Tab::Scan, cx);
                view.add_report(sample(), None, window, cx);
                assert!(view.search.read(cx).value().is_empty());
                assert!(view.selected.is_none());
                view
            });
            desktop = Some(view.clone());
            Root::new(view, window, cx)
        });
        drop(storage);
        let desktop = desktop.unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            window.click(("report-tab", 1u64), cx);
            window.render_frame(cx);
            let view = desktop.read(cx);
            assert_eq!(view.reports.len(), 2);
            assert_eq!(view.active_report, Some(1));
            assert!(matches!(view.tab, Tab::Findings));
            assert!(!view.search.read(cx).value().is_empty());
            assert!(!view.filters[1].1.read(cx).value().is_empty());
            assert_eq!(view.visible_filters, vec![1]);
            assert_eq!(view.columns[0].1, 333.);
            assert!(view.raw_open && !view.unique);
            assert_eq!(view.finding_sort, Some((FindingColumn::Line, true)));
            assert!(view.selected.is_some());
            assert!(!view.detail.is_empty());
            window.click(("close-report", 2u64), cx);
            assert_eq!(desktop.read(cx).active_report, Some(1));
            assert!(temporary_path.exists());
            window.render_frame(cx);
            window.click(("close-report", 1u64), cx);
            window.render_frame(cx);
            assert!(desktop.read(cx).reports.is_empty());
            assert!(desktop.read(cx).data.is_none());
            assert!(matches!(desktop.read(cx).tab, Tab::Scan));
        })
        .unwrap();
        assert!(!temporary_path.exists());
    }

    #[gpui_kit::test]
    fn findings_columns_resize_scroll_and_theme_controls_work(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let mut desktop = None;
        let handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| {
                let mut desktop = Desktop::new(PathBuf::from("kingfisher"), None, window, cx);
                let mut report = ReportData::default();
                report.read_bytes(include_bytes!("../../docs/viewer/sample-report.json")).unwrap();
                let sample = report.findings[0].clone();
                report.findings = (0..80)
                    .map(|index| {
                        let mut finding = sample.clone();
                        finding.fingerprint = format!("fixture-{index}");
                        finding
                    })
                    .collect();
                desktop.data = Some(Arc::new(report));
                desktop.refilter(cx);
                desktop.tab = Tab::Findings;
                desktop
            });
            desktop = Some(view.clone());
            Root::new(view, window, cx)
        });
        let desktop = desktop.unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).columns.len(), 4);
            assert!(desktop.read(cx).findings_scroll.is_scrollable());
            let bounds = window.find("findings-horizontal").bounds();
            window.drag(
                gpui_kit::point(bounds.right() - px(5.), bounds.top() + px(44.)),
                gpui_kit::point(bounds.right() - px(5.), bounds.bottom() - px(24.)),
                cx,
            );
            assert!(
                gpui_kit::component::scroll::ScrollbarHandle::offset(
                    &desktop.read(cx).findings_scroll
                )
                .y < px(0.)
            );
            window.drag_to(("resize-column", 0usize), ("sort-finding", 1usize), cx);
            assert!(desktop.read(cx).columns[0].1 > FindingColumn::Rule.width());
            assert!(desktop.read(cx).resizing.is_none());
            window.scroll(
                "findings-horizontal",
                gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(-300.), px(0.))),
                cx,
            );
            assert!(desktop.read(cx).horizontal_scroll.offset().x < px(0.));
            window.click("finding-columns", cx);
            window.press("down", cx);
            window.press("enter", cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).columns.len(), 3);
            assert!(!desktop.read(cx).columns.iter().any(|(c, _)| *c == FindingColumn::Rule));
            window.click("finding-columns", cx);
            window.press("down", cx);
            window.press("enter", cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).columns.len(), 4);
            window.click("theme-mode", cx);
            window.press("down", cx);
            window.press("down", cx);
            window.press("enter", cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).theme_mode, Some(ThemeMode::Light));
            assert!(!cx.theme().is_dark());
            assert_eq!(color(BG), gpui_kit::rgb(0xf7f8fa).into());
            window.click("theme-mode", cx);
            for _ in 0..3 {
                window.press("down", cx);
            }
            window.press("enter", cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).theme_mode, Some(ThemeMode::Dark));
            assert!(cx.theme().is_dark());
            assert_eq!(color(BG), gpui_kit::rgb(BG).into());
            window.click("theme-mode", cx);
            window.press("down", cx);
            window.press("enter", cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(desktop.read(cx).theme_mode, None);
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn copy_command_and_failure_activity_are_reachable(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| Desktop::new(PathBuf::from("kingfisher"), None, window, cx));
            Root::new(view, window, cx)
        });
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            window.click("scan-target", cx);
            window.input("project with spaces", cx);
            window.render_frame(cx);
            window.click("copy-command", cx);
            let copied = cx.read_from_clipboard().unwrap().text().unwrap();
            assert!(copied.contains("project with spaces"));
            assert!(copied.contains('\n'));
            assert!(!copied.contains("--git-clone-dir"));
            assert!(!copied.contains("--no-validate"));
            assert!(!copied.contains("--redact"));
            window.click("Activity", cx);
            window.render_frame(cx);
            assert!(window.find("copy-log").visible());
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn rules_and_settings_generate_literal_cli_arguments(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let directory = tempfile::tempdir().unwrap();
        let rule_file = directory.path().join("team's rules.toml");
        std::fs::write(&rule_file, "").unwrap();
        let rule_folder = directory.path().join("more rules");
        std::fs::create_dir(&rule_folder).unwrap();
        let mut desktop = None;
        let handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| {
                Desktop::new(
                    PathBuf::from("kingfisher"),
                    Some(directory.path().as_os_str().to_owned()),
                    window,
                    cx,
                )
            });
            desktop = Some(view.clone());
            Root::new(view, window, cx)
        });
        let desktop = desktop.unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert!(window.find("add-rule-files").visible());
            assert!(window.find("add-rule-folder").visible());
            window.click("builtin-rules", cx);
            desktop.update(cx, |this, cx| {
                assert!(this.preview(cx).is_err());
                this.rule_paths = vec![rule_file.clone(), rule_folder.clone()];
                cx.notify();
            });
            window.render_frame(cx);
            desktop.update(cx, |this, cx| {
                let command = this
                    .options(cx)
                    .command(Path::new("kingfisher"), Path::new("report.json"))
                    .unwrap();
                let args: Vec<_> = command.get_args().map(OsString::from).collect();
                assert!(args.contains(&OsString::from("--load-builtins=false")));
                for path in [&rule_file, &rule_folder] {
                    let mut expected = OsString::from("--rules-path=");
                    expected.push(path);
                    assert!(args.contains(&expected));
                }
            });
            window.click("advanced-options", cx);
            window.render_frame(cx);
            assert!(window.find("settings-category").visible());
            window.click("option-search", cx);
            window.input("Parallel workers", cx);
            window.render_frame(cx);
            let jobs = desktop
                .read(cx)
                .advanced_options
                .iter()
                .position(|option| option.spec.flag == "jobs")
                .unwrap();
            window.click(("advanced-value", jobs), cx);
            window.input("4", cx);
            window.render_frame(cx);
            window.click("close-settings", cx);
            window.render_frame(cx);
            window.click("copy-command", cx);
            assert!(cx.read_from_clipboard().unwrap().text().unwrap().contains("--jobs=4"));
            window.click(("remove-rules", 0usize), cx);
            assert_eq!(desktop.read(cx).rule_paths, vec![rule_folder.clone()]);
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn scan_controls_remain_reachable_at_the_minimum_window_size(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let handle = cx.open_window(size(px(1000.), px(680.)), |window, cx| {
            let view = cx.new(|cx| Desktop::new(PathBuf::from("kingfisher"), None, window, cx));
            Root::new(view, window, cx)
        });
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            window.scroll(
                "scan-scroll",
                gpui_kit::ScrollDelta::Pixels(gpui_kit::point(px(0.), px(-800.))),
                cx,
            );
            window.render_frame(cx);
            let start = window.find("start");
            assert!(start.visible());
            assert!(start.bounds().bottom() <= window.viewport_size().height);
            assert!(start.bounds().right() <= window.viewport_size().width);
            assert!(window.find("Activity").visible());
        })
        .unwrap();
    }

    #[gpui_kit::test]
    fn native_report_tabs_render_and_show_evidence(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            configure_theme(cx);
        });
        let mut desktop_view = None;
        let handle = cx.open_window(size(px(1280.), px(850.)), |window, cx| {
            let view = cx.new(|cx| {
                let mut desktop = Desktop::new(PathBuf::from("kingfisher"), None, window, cx);
                let mut report = ReportData::default();
                report.read_bytes(include_bytes!("../../docs/viewer/sample-report.json")).unwrap();
                desktop.data = Some(Arc::new(report));
                desktop.refilter(cx);
                desktop.tab = Tab::Findings;
                desktop
            });
            desktop_view = Some(view.clone());
            Root::new(view, window, cx)
        });
        let desktop_view = desktop_view.unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            window.click(("finding", 0usize), cx);
            window.render_frame(cx);
            assert!(window.find("copy-snippet").visible());
            window.click_at("snippet-selection", gpui_kit::point(px(20.), px(20.)), cx);
            window.press("secondary-a", cx);
            window.press("secondary-c", cx);
            let expected = desktop_view.read(cx).data.as_ref().unwrap().findings[0].snippet.clone();
            assert_eq!(cx.read_from_clipboard().unwrap().text().unwrap().trim(), expected.trim());
            window.click("copy-detail", cx);
            assert!(cx.read_from_clipboard().unwrap().text().unwrap().contains("finding"));
            window.click(("finding", 0usize), cx);
            window.press("down", cx);
            window.render_frame(cx);
            assert_eq!(desktop_view.read(cx).selected, Some(1));
            window.click(("sort-finding", 2usize), cx);
            window.render_frame(cx);
            assert_eq!(desktop_view.read(cx).filtered, vec![2, 0, 1]);
            assert_eq!(desktop_view.read(cx).selected, Some(1));
            window.click(("sort-finding", 2usize), cx);
            window.render_frame(cx);
            assert_eq!(desktop_view.read(cx).filtered, vec![1, 0, 2]);
            window.click("copy-detail", cx);
            assert!(cx.read_from_clipboard().unwrap().text().unwrap().contains("finding"));
            window.click("finding-filters", cx);
            window.render_frame(cx);
            window.press("down", cx);
            window.press("enter", cx);
        })
        .unwrap();
        // Let the popup's deferred dismissal complete, as it does between native events.
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert!(window.find(("filter-choice", 0usize)).visible());
            window.click(("remove-filter", 0usize), cx);
        })
        .unwrap();
        cx.update_window(handle.into(), |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find(("filter-choice", 0usize)).is_none());
            window.click("active-only", cx);
            window.render_frame(cx);
            let desktop = desktop_view.read(cx);
            assert!(desktop.active_only);
            assert!(
                desktop
                    .filtered
                    .iter()
                    .all(|index| desktop.data.as_ref().unwrap().findings[*index].active())
            );
            for tab in ["Coverage", "Blast radius", "Overview", "New scan"] {
                window.click(tab, cx);
                window.render_frame(cx);
            }
            // An empty target is an actionable error and automatically opens Activity.
            window.click("start", cx);
            window.render_frame(cx);
            window.click("copy-log", cx);
            assert!(cx.read_from_clipboard().unwrap().text().unwrap().contains("Choose a file"));
        })
        .unwrap();
    }
}
