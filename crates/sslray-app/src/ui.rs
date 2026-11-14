use crate::certificate_gate::{CertificateApproval, CertificateTarget};
use crate::certificate_ui::{self, CertificateChoice};
use crate::i18n::{self, Language, Text as T, text};
use crate::profiles::ProfileLibrary;
use crate::runtime::{ConnectionState, Controller, Snapshot};
use crate::system_info::{self, AdapterInfo};
use crate::tray;
use anyhow::{Context, Result};
use directories::ProjectDirs;
use eframe::egui::{self, Align, Color32, FontId, RichText, Stroke, Vec2};
use serde::{Deserialize, Serialize};
use sslray_core::config::{CryptoMode, Profile, RouteMode, TransportMode, VpnProtocol};
use sslray_core::crypto::{self, CertificateReport};
use std::{path::PathBuf, time::Duration};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Theme {
    #[default]
    Light,
    Dark,
}

#[derive(Clone, Copy)]
struct Palette {
    ink: Color32,
    muted: Color32,
    blue: Color32,
    pale: Color32,
    background: Color32,
    surface: Color32,
    line: Color32,
    green: Color32,
    danger: Color32,
    warning: Color32,
    warning_bg: Color32,
}

fn palette(ui: &egui::Ui) -> Palette {
    theme_palette(ui.visuals().dark_mode)
}

fn theme_palette(dark: bool) -> Palette {
    if dark {
        Palette {
            ink: Color32::from_rgb(232, 237, 247),
            muted: Color32::from_rgb(168, 182, 204),
            blue: Color32::from_rgb(72, 139, 255),
            pale: Color32::from_rgb(32, 52, 84),
            background: Color32::from_rgb(16, 23, 35),
            surface: Color32::from_rgb(24, 33, 48),
            line: Color32::from_rgb(54, 68, 88),
            green: Color32::from_rgb(61, 202, 152),
            danger: Color32::from_rgb(255, 140, 128),
            warning: Color32::from_rgb(241, 196, 103),
            warning_bg: Color32::from_rgb(61, 46, 25),
        }
    } else {
        Palette {
            ink: Color32::from_rgb(25, 38, 59),
            muted: Color32::from_rgb(79, 97, 121),
            blue: Color32::from_rgb(35, 94, 221),
            pale: Color32::from_rgb(234, 241, 255),
            background: Color32::from_rgb(245, 247, 251),
            surface: Color32::WHITE,
            line: Color32::from_rgb(211, 220, 233),
            green: Color32::from_rgb(15, 133, 89),
            danger: Color32::from_rgb(180, 54, 43),
            warning: Color32::from_rgb(139, 91, 18),
            warning_bg: Color32::from_rgb(255, 246, 224),
        }
    }
}

#[derive(Clone, Copy)]
enum ProfileAction {
    Select(u64),
    New,
    Duplicate,
    Delete,
}

#[derive(Clone, Copy)]
enum ProfileDialog {
    Unsaved(ProfileAction),
    Delete,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Settings,
    Logs,
    AppSettings,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct UiPreferences {
    language: Language,
    theme: Theme,
}

struct Notice {
    title: T,
    detail: Option<String>,
}
impl Notice {
    fn plain(title: T) -> Self {
        Self {
            title,
            detail: None,
        }
    }
    fn error(title: T, detail: impl std::fmt::Display) -> Self {
        Self {
            title,
            detail: Some(detail.to_string()),
        }
    }
    fn display(&self, language: Language) -> String {
        match &self.detail {
            Some(detail) => format!(
                "{}: {}",
                text(language, self.title),
                i18n::diagnostic(language, detail)
            ),
            None => text(language, self.title).into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterTarget {
    session_generation: u64,
    name: String,
    address: Option<String>,
    configured_mtu: u16,
}

impl AdapterTarget {
    fn from_snapshot(snapshot: &Snapshot, busy: bool, configured_mtu: u16) -> Option<Self> {
        // Failed sessions can still be cleaning up. The worker's final
        // Disconnected acknowledgment, rather than the headline state alone,
        // ends ownership of the interface for display purposes.
        if !busy
            || !matches!(
                snapshot.state,
                ConnectionState::Connected
                    | ConnectionState::Disconnecting
                    | ConnectionState::Failed
            )
        {
            return None;
        }
        let name = snapshot
            .interface
            .as_ref()
            .filter(|name| !name.is_empty())?;
        Some(Self {
            session_generation: snapshot.session_generation,
            name: name.clone(),
            address: snapshot.address.clone(),
            configured_mtu,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterRequest {
    generation: u64,
    target: AdapterTarget,
}

struct AdapterResponse {
    request: AdapterRequest,
    result: std::result::Result<Option<AdapterInfo>, String>,
}

#[derive(Default)]
struct AdapterDisplay {
    target: Option<AdapterTarget>,
    generation: u64,
    metadata: Option<AdapterInfo>,
    error: Option<String>,
}

impl AdapterDisplay {
    fn select(&mut self, target: Option<AdapterTarget>) -> bool {
        if self.target == target {
            return false;
        }
        self.target = target;
        self.generation = self.generation.saturating_add(1);
        self.metadata = None;
        self.error = None;
        true
    }

    fn refresh(&mut self) -> Option<AdapterRequest> {
        let target = self.target.clone()?;
        self.generation = self.generation.saturating_add(1);
        self.metadata = None;
        self.error = None;
        Some(AdapterRequest {
            generation: self.generation,
            target,
        })
    }

    fn accept(&mut self, response: AdapterResponse) -> bool {
        if response.request.generation != self.generation
            || self.target.as_ref() != Some(&response.request.target)
        {
            return false;
        }
        self.metadata = None;
        self.error = None;
        match response.result {
            Ok(Some(adapter)) if adapter.name == response.request.target.name => {
                self.metadata = Some(adapter);
            }
            Ok(Some(_)) => self.error = Some("Unexpected interface in session query".into()),
            Ok(None) => {}
            Err(error) => self.error = Some(error),
        }
        true
    }
}

struct CertificateQuery {
    target: CertificateTarget,
    receiver: std::sync::mpsc::Receiver<std::result::Result<CertificateReport, String>>,
}

struct CertificateReview {
    target: CertificateTarget,
    report: CertificateReport,
    remember: bool,
}

struct App {
    controller: Controller,
    profile: Profile,
    profiles: ProfileLibrary,
    profile_dialog: Option<ProfileDialog>,
    profiles_writable: bool,
    remember_password: bool,
    confirm_password_storage: bool,
    password_dialog: bool,
    rejection_handled: bool,
    password: String,
    otp: String,
    use_otp: bool,
    show_password: bool,
    route_text: String,
    page: Page,
    notice: Option<Notice>,
    tray: Option<tray::Tray>,
    hidden: bool,
    quitting: bool,
    config_dir: Option<PathBuf>,
    preferences_path: Option<PathBuf>,
    language: Language,
    theme: Theme,
    challenge_prompted: bool,
    challenge_focus: bool,
    crypto_backend: String,
    gm_available: bool,
    adapter_display: AdapterDisplay,
    adapter_query: Option<std::sync::mpsc::Receiver<AdapterResponse>>,
    authorization_retry: bool,
    pending_password: Option<Zeroizing<String>>,
    pending_otp: Option<Zeroizing<String>>,
    certificate_query: Option<CertificateQuery>,
    certificate_review: Option<CertificateReview>,
    certificate_approval: Option<CertificateApproval>,
}

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SSLRay")
            .with_inner_size([1060.0, 790.0])
            .with_min_inner_size([940.0, 650.0])
            .with_icon(egui::IconData {
                rgba: tray::icon_rgba(64),
                width: 64,
                height: 64,
            }),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native("SSLRay", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config_dir =
            ProjectDirs::from("tech", "SSLRay", "SSLRay").map(|dir| dir.config_dir().to_path_buf());
        let preferences_path = config_dir
            .as_ref()
            .map(|dir| dir.join("ui-preferences.json"));
        let mut notice = None;
        let preferences = preferences_path
            .as_ref()
            .filter(|path| path.exists())
            .and_then(|path| {
                match std::fs::read(path).and_then(|bytes| {
                    serde_json::from_slice::<UiPreferences>(&bytes).map_err(std::io::Error::other)
                }) {
                    Ok(preferences) => Some(preferences),
                    Err(error) => {
                        notice = Some(Notice::error(T::ReadPrefsFailed, error));
                        None
                    }
                }
            })
            .unwrap_or_default();
        let language = preferences.language;
        let theme = preferences.theme;
        configure(&cc.egui_ctx, theme);
        let (profiles, profiles_writable) = match config_dir.as_ref() {
            Some(directory) => match ProfileLibrary::load(directory) {
                Ok(profiles) => (profiles, true),
                Err(error) => {
                    notice = Some(Notice::error(T::ReadProfilesFailed, error));
                    (ProfileLibrary::default(), false)
                }
            },
            None => (ProfileLibrary::default(), false),
        };
        let profile = profiles.selected().profile.clone();
        let remember_password = profiles.selected().saved_password.is_some();
        let password = profiles
            .selected()
            .saved_password
            .clone()
            .unwrap_or_default();
        let system_tray = match tray::Tray::new(cc.egui_ctx.clone(), language) {
            Ok(tray) => Some(tray),
            Err(error) => {
                notice = Some(Notice::error(T::TrayUnavailable, error));
                None
            }
        };
        let capabilities = sslray_core::crypto::capabilities();
        Self {
            crypto_backend: capabilities.backend,
            gm_available: capabilities.gm_tls13,
            route_text: profile.routes.join("\n"),
            profile,
            profiles,
            profiles_writable,
            profile_dialog: None,
            remember_password,
            confirm_password_storage: false,
            password_dialog: false,
            rejection_handled: false,
            controller: Controller::new(),
            password,
            otp: String::new(),
            use_otp: false,
            show_password: false,
            page: Page::Overview,
            notice,
            tray: system_tray,
            hidden: false,
            quitting: false,
            config_dir,
            preferences_path,
            language,
            theme,
            challenge_prompted: false,
            challenge_focus: false,
            adapter_display: AdapterDisplay::default(),
            adapter_query: None,
            authorization_retry: false,
            pending_password: None,
            pending_otp: None,
            certificate_query: None,
            certificate_review: None,
            certificate_approval: None,
        }
    }

    fn save_preferences(&self) -> Result<()> {
        let path = self
            .preferences_path
            .as_ref()
            .context("Cannot locate the application configuration directory")?;
        let dir = path.parent().context("Invalid configuration directory")?;
        std::fs::create_dir_all(dir)?;
        let temporary = path.with_extension("tmp");
        std::fs::write(
            &temporary,
            serde_json::to_vec_pretty(&UiPreferences {
                language: self.language,
                theme: self.theme,
            })?,
        )?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    fn language_selector(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let previous = self.language;
        ui.vertical(|ui| {
            ui.label(
                RichText::new(text(self.language, T::Language))
                    .size(12.0)
                    .color(colors.muted),
            );
            egui::ComboBox::from_id_salt("interface-language")
                .width(200.0)
                .height(160.0)
                .selected_text(self.language.label())
                .show_ui(ui, |ui| {
                    for language in [Language::ZhCn, Language::En] {
                        ui.selectable_value(&mut self.language, language, language.label());
                    }
                });
        });
        if self.language != previous {
            if let Some(tray) = &mut self.tray {
                tray.set_language(self.language);
            }
            if let Err(error) = self.save_preferences() {
                self.notice = Some(Notice::error(T::UiPrefsFailed, error));
            }
            ui.ctx().request_repaint();
        }
    }

    fn theme_selector(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let previous = self.theme;
        ui.vertical(|ui| {
            ui.label(
                RichText::new(text(self.language, T::Theme))
                    .size(12.0)
                    .color(colors.muted),
            );
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.theme,
                    Theme::Light,
                    text(self.language, T::ThemeLight),
                );
                ui.selectable_value(
                    &mut self.theme,
                    Theme::Dark,
                    text(self.language, T::ThemeDark),
                );
            });
        });
        if self.theme != previous {
            apply_theme(ui.ctx(), self.theme);
            if let Err(error) = self.save_preferences() {
                self.notice = Some(Notice::error(T::UiPrefsFailed, error));
            }
            ui.ctx().request_repaint();
        }
    }

    fn password_storage_path(&self) -> Option<PathBuf> {
        self.config_dir
            .as_ref()
            .map(|directory| directory.join("profiles.json"))
    }

    fn password_storage_option(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let lang = self.language;
        let mut requested = self.remember_password;
        if ui
            .add_enabled(
                self.profiles_writable,
                egui::Checkbox::new(&mut requested, text(lang, T::RememberPassword)),
            )
            .changed()
        {
            if requested {
                self.confirm_password_storage = true;
            } else {
                self.remember_password = false;
            }
        }
        if !self.profiles_writable {
            ui.label(
                RichText::new(text(lang, T::SavePasswordUnavailable))
                    .size(12.0)
                    .color(colors.warning),
            );
        }
    }

    fn profile_dialogs(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.profile_dialog else {
            return;
        };
        let lang = self.language;
        let mut close = false;
        let mut perform = None;
        let response = egui::Modal::new(egui::Id::new("profile-action-dialog")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(
                RichText::new(text(
                    lang,
                    match dialog {
                        ProfileDialog::Unsaved(_) => T::UnsavedChanges,
                        ProfileDialog::Delete => T::DeleteProfileTitle,
                    },
                ))
                .size(19.0)
                .strong(),
            );
            ui.add_space(10.0);
            ui.label(&self.profile.name);
            ui.label(text(
                lang,
                match dialog {
                    ProfileDialog::Unsaved(_) => T::UnsavedProfilePrompt,
                    ProfileDialog::Delete => T::DeleteProfilePrompt,
                },
            ));
            if let Some(notice) = &self.notice {
                ui.label(notice.display(lang));
            }
            ui.add_space(14.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button(text(lang, T::Cancel)).clicked() {
                    close = true;
                }
                match dialog {
                    ProfileDialog::Unsaved(action) => {
                        if ui.button(text(lang, T::DiscardChanges)).clicked() {
                            close = true;
                            perform = Some(action);
                        }
                        if ui.button(text(lang, T::SaveAndContinue)).clicked() {
                            match self.save() {
                                Ok(()) => {
                                    close = true;
                                    perform = Some(action);
                                }
                                Err(error) => {
                                    self.notice = Some(Notice::error(T::SaveFailed, error))
                                }
                            }
                        }
                    }
                    ProfileDialog::Delete => {
                        if ui.button(text(lang, T::DeleteProfile)).clicked() {
                            close = true;
                            perform = Some(ProfileAction::Delete);
                        }
                    }
                }
            });
        });
        if close || response.should_close() {
            self.profile_dialog = None;
        }
        if let Some(action) = perform {
            self.perform_profile_action(action);
        }
    }

    fn credential_dialogs(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        if self.confirm_password_storage {
            let mut close = false;
            let response =
                egui::Modal::new(egui::Id::new("confirm-plaintext-storage")).show(ctx, |ui| {
                    ui.set_width(480.0);
                    ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(text(lang, T::ConfirmSavePassword))
                                    .size(19.0)
                                    .strong(),
                            )
                            .wrap()
                            .halign(Align::Min),
                        );
                        ui.add_space(10.0);
                        ui.add(
                            egui::Label::new(text(lang, T::PlaintextPasswordWarning))
                                .wrap()
                                .halign(Align::Min),
                        );
                        if let Some(path) = self.password_storage_path() {
                            ui.add_space(8.0);
                            let mut path_text = egui::text::LayoutJob::simple(
                                path.display().to_string(),
                                FontId::monospace(12.0),
                                ui.visuals().text_color(),
                                ui.available_width(),
                            );
                            path_text.wrap.break_anywhere = true;
                            ui.add(
                                egui::Label::new(path_text)
                                    .wrap()
                                    .halign(Align::Min)
                                    .selectable(true),
                            );
                        }
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui.button(text(lang, T::Cancel)).clicked() {
                                close = true;
                            }
                            if ui.button(text(lang, T::Confirm)).clicked() {
                                self.remember_password = true;
                                close = true;
                            }
                        });
                    });
                });
            if close || response.should_close() {
                self.confirm_password_storage = false;
            }
            return;
        }
        if !self.password_dialog {
            return;
        }
        let mut cancel = false;
        let mut submit = false;
        let response = egui::Modal::new(egui::Id::new("connection-password")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(
                RichText::new(text(lang, T::PasswordRequiredTitle))
                    .size(19.0)
                    .strong(),
            );
            ui.add_space(10.0);
            ui.label(format!(
                "{}: {}",
                text(lang, T::PasswordForProfile),
                self.profile.name
            ));
            ui.label(format!(
                "{}: {}",
                text(lang, T::Username),
                self.profile.username
            ));
            if let Some(notice) = &self.notice {
                ui.label(notice.display(lang));
            }
            ui.add_space(10.0);
            password_edit(
                ui,
                &mut self.password,
                &mut self.show_password,
                lang,
                egui::Margin::symmetric(4, 2),
            );
            ui.add_space(10.0);
            self.password_storage_option(ui);
            if !self.remember_password {
                ui.label(text(lang, T::PasswordNotSaved));
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button(text(lang, T::Cancel)).clicked() {
                    cancel = true;
                }
                if ui
                    .add_enabled(
                        !self.password.is_empty(),
                        egui::Button::new(text(lang, T::ContinueConnect)),
                    )
                    .clicked()
                {
                    submit = true;
                }
            });
        });
        if cancel || response.should_close() {
            self.password_dialog = false;
            self.password.zeroize();
            self.show_password = false;
            self.certificate_approval = None;
        } else if submit {
            self.password_dialog = false;
            self.show_password = false;
            self.connect();
        }
    }

    fn busy(&self) -> bool {
        self.controller.is_busy()
    }

    fn apply_routes(&mut self) {
        self.profile.use_server_routes = self.profile.route_mode != RouteMode::ManualOnly;
        self.profile.routes = self
            .route_text
            .lines()
            .map(str::trim)
            .filter(|route| !route.is_empty())
            .map(str::to_owned)
            .collect();
    }

    fn persist_library(&self, profiles: &ProfileLibrary) -> Result<()> {
        anyhow::ensure!(
            self.profiles_writable,
            "Profile storage is unavailable; repair the profile file before saving"
        );
        let directory = self
            .config_dir
            .as_ref()
            .context("Cannot locate the application configuration directory")?;
        profiles.save(directory)
    }

    fn save(&mut self) -> Result<()> {
        self.apply_routes();
        let mut candidate = self.profiles.clone();
        candidate.update_selected(self.profile.clone())?;
        anyhow::ensure!(
            !self.remember_password || !self.password.is_empty(),
            "Enter the password to save"
        );
        candidate.set_saved_password(self.remember_password.then(|| self.password.clone()))?;
        self.persist_library(&candidate)?;
        self.profile = candidate.selected().profile.clone();
        self.profiles = candidate;
        Ok(())
    }

    fn dirty(&self) -> bool {
        let mut draft = self.profile.clone();
        draft.use_server_routes = draft.route_mode != RouteMode::ManualOnly;
        draft.routes = self
            .route_text
            .lines()
            .map(str::trim)
            .filter(|route| !route.is_empty())
            .map(str::to_owned)
            .collect();
        !self.profiles.is_current_profile(&draft)
            || self.remember_password != self.profiles.selected().saved_password.is_some()
            || (self.remember_password
                && self.profiles.selected().saved_password.as_deref()
                    != Some(self.password.as_str()))
    }

    fn request_profile_action(&mut self, action: ProfileAction) {
        if self.busy() {
            return;
        }
        if matches!(action, ProfileAction::Select(id) if id == self.profiles.selected_id) {
            return;
        }
        if matches!(action, ProfileAction::Delete) {
            self.profile_dialog = Some(ProfileDialog::Delete);
        } else if self.dirty() {
            self.profile_dialog = Some(ProfileDialog::Unsaved(action));
        } else {
            self.perform_profile_action(action);
        }
    }

    fn perform_profile_action(&mut self, action: ProfileAction) {
        let result = (|| -> Result<ProfileLibrary> {
            let mut candidate = self.profiles.clone();
            match action {
                ProfileAction::Select(id) => candidate.select(id)?,
                ProfileAction::New => {
                    let profile = Profile {
                        name: candidate.unique_name(text(self.language, T::NewProfileName)),
                        ..Profile::default()
                    };
                    candidate.insert(profile)?;
                }
                ProfileAction::Duplicate => {
                    let mut profile = candidate.selected().profile.clone();
                    profile.name = candidate.unique_name(&format!(
                        "{} {}",
                        profile.name,
                        text(self.language, T::DuplicateNameSuffix)
                    ));
                    // The copy starts without a saved password.
                    candidate.insert(profile)?;
                }
                ProfileAction::Delete => candidate.remove_selected()?,
            }
            self.persist_library(&candidate)?;
            Ok(candidate)
        })();
        match result {
            Ok(profiles) => {
                self.clear_certificate_check();
                self.password.zeroize();
                self.otp.zeroize();
                self.profiles = profiles;
                self.profile = self.profiles.selected().profile.clone();
                self.password = self
                    .profiles
                    .selected()
                    .saved_password
                    .clone()
                    .unwrap_or_default();
                self.remember_password = self.profiles.selected().saved_password.is_some();
                self.route_text = self.profile.routes.join("\n");
                self.use_otp = false;
                self.show_password = false;
                self.password_dialog = false;
                self.rejection_handled = false;
                self.authorization_retry = false;
                self.pending_password = None;
                self.pending_otp = None;
                self.controller.reset_snapshot();
                self.notice = Some(Notice::plain(match action {
                    ProfileAction::Select(_) => T::ProfileChanged,
                    ProfileAction::New | ProfileAction::Duplicate => T::ProfileCreated,
                    ProfileAction::Delete => T::ProfileDeleted,
                }));
                if !matches!(action, ProfileAction::Select(_)) {
                    self.page = Page::Settings;
                }
            }
            Err(error) => self.notice = Some(Notice::error(T::ProfileActionFailed, error)),
        }
    }

    fn profile_selector(&mut self, ui: &mut egui::Ui, management: bool) {
        let lang = self.language;
        let colors = palette(ui);
        let busy = self.busy();
        card(ui).show(ui, |ui| {
            field_label(ui, text(lang, T::SelectProfile));
            let mut selected = self.profiles.selected_id;
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    egui::ComboBox::from_id_salt(if management {
                        "settings-profile"
                    } else {
                        "overview-profile"
                    })
                    .width((ui.available_width() - 160.0).max(220.0))
                    .selected_text(&self.profiles.selected().profile.name)
                    .show_ui(ui, |ui| {
                        for entry in &self.profiles.entries {
                            ui.selectable_value(&mut selected, entry.id, &entry.profile.name);
                        }
                    });
                });
                if !management && ui.button(text(lang, T::ManageProfiles)).clicked() {
                    self.page = Page::Settings;
                }
            });
            if selected != self.profiles.selected_id {
                self.request_profile_action(ProfileAction::Select(selected));
            }
            if management {
                ui.add_space(9.0);
                ui.horizontal(|ui| {
                    for (label, action) in [
                        (T::NewProfile, ProfileAction::New),
                        (T::DuplicateProfile, ProfileAction::Duplicate),
                    ] {
                        if ui
                            .add_enabled(!busy, egui::Button::new(text(lang, label)))
                            .clicked()
                        {
                            self.request_profile_action(action);
                        }
                    }
                    let can_delete = self.profiles.entries.len() > 1;
                    if ui
                        .add_enabled(
                            !busy && can_delete,
                            egui::Button::new(text(lang, T::DeleteProfile)),
                        )
                        .on_disabled_hover_text(text(lang, T::LastProfileHelp))
                        .clicked()
                    {
                        self.request_profile_action(ProfileAction::Delete);
                    }
                });
            }
            if self.dirty() {
                ui.add_space(6.0);
                ui.label(RichText::new(text(lang, T::UnsavedChanges)).color(colors.warning));
            }
            if busy {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(text(lang, T::DisconnectToSwitch))
                        .size(12.0)
                        .color(colors.muted),
                );
            }
            if !self.profiles_writable {
                ui.label(
                    RichText::new(text(lang, T::ProfileStorageBlocked))
                        .size(12.0)
                        .color(colors.danger),
                );
            }
        });
        ui.add_space(16.0);
    }

    fn connect(&mut self) {
        if self.busy() || self.certificate_query.is_some() || self.certificate_review.is_some() {
            return;
        }
        self.show_password = false;
        self.apply_routes();
        if self.profile.protocol != VpnProtocol::OpenVpn && self.profile.username.trim().is_empty()
        {
            self.page = Page::Settings;
            self.notice = Some(Notice::plain(T::InputCredentials));
            return;
        }
        if self.profile.protocol == VpnProtocol::OpenVpn {
            if self.profile.openvpn_config.trim().is_empty() {
                self.page = Page::Settings;
                self.notice = Some(Notice::plain(T::OvpnPathRequired));
                return;
            }
            if self.profile.crypto != CryptoMode::Standard {
                self.page = Page::Settings;
                self.notice = Some(Notice::plain(T::OvpnGmUnsupported));
                return;
            }
        }
        if let Err(error) = self.profile.validate() {
            self.page = Page::Settings;
            self.notice = Some(Notice::error(T::InvalidProfile, error));
            return;
        }
        let password_required = match sslray_core::openvpn::requires_password(&self.profile) {
            Ok(required) => required,
            Err(error) => {
                self.page = Page::Settings;
                self.notice = Some(Notice::error(T::InvalidProfile, error));
                return;
            }
        };
        if password_required && self.profile.username.trim().is_empty() {
            self.page = Page::Settings;
            self.notice = Some(Notice::plain(T::InputCredentials));
            return;
        }
        if password_required && self.password.is_empty() {
            self.password_dialog = true;
            return;
        }
        if (self.remember_password || self.profiles.selected().saved_password.is_some())
            && let Err(error) = self.save()
        {
            self.notice = Some(Notice::error(T::SaveFailed, error));
            return;
        }
        self.rejection_handled = false;
        if self.use_otp && (self.otp.is_empty() || self.otp.len() > 31 || self.otp.contains('\0')) {
            self.page = Page::Settings;
            self.notice = Some(Notice::plain(T::InvalidOtp));
            return;
        }
        let connection_profile = if self.profile.protocol != VpnProtocol::OpenVpn
            && self.profile.certificate_sha256.is_empty()
        {
            match self.certificate_approval.as_ref().and_then(|approval| {
                approval.connection_profile(self.profiles.selected_id, &self.profile)
            }) {
                Some(profile) => profile,
                None => {
                    self.certificate_approval = None;
                    self.start_certificate_check();
                    return;
                }
            }
        } else {
            self.profile.clone()
        };
        let password = if self.remember_password {
            self.password.clone()
        } else {
            std::mem::take(&mut self.password)
        };
        let otp = if self.use_otp {
            Some(std::mem::take(&mut self.otp))
        } else {
            self.otp.zeroize();
            None
        };
        self.pending_password = Some(Zeroizing::new(password.clone()));
        self.pending_otp = otp.as_ref().map(|value| Zeroizing::new(value.clone()));
        self.authorization_retry = false;
        self.certificate_approval = None;
        match self.controller.connect(connection_profile, password, otp) {
            Ok(()) => {
                self.page = Page::Overview;
                self.notice = None;
                self.show_password = false;
            }
            Err(error) => {
                self.pending_password = None;
                self.pending_otp = None;
                self.notice = Some(Notice::error(T::ConnectFailed, format!("{error:#}")));
            }
        }
    }

    fn clear_certificate_check(&mut self) {
        self.certificate_query = None;
        self.certificate_review = None;
        self.certificate_approval = None;
    }

    fn start_certificate_check(&mut self) {
        let target = CertificateTarget::new(self.profiles.selected_id, &self.profile);
        let mut profile = self.profile.clone();
        // Certificate discovery never needs account names or login secrets.
        profile.username.clear();
        let (sender, receiver) = std::sync::mpsc::channel();
        self.certificate_query = Some(CertificateQuery { target, receiver });
        std::thread::spawn(move || {
            let result = crypto::check_certificate(&profile).map_err(|error| format!("{error:#}"));
            let _ = sender.send(result);
        });
    }

    fn poll_certificate_check(&mut self, ctx: &egui::Context) {
        let current = CertificateTarget::new(self.profiles.selected_id, &self.profile);
        if self
            .certificate_query
            .as_ref()
            .is_some_and(|query| query.target != current)
            || self
                .certificate_review
                .as_ref()
                .is_some_and(|review| review.target != current)
            || self
                .certificate_approval
                .as_ref()
                .is_some_and(|approval| approval.target != current)
        {
            self.clear_certificate_check();
            return;
        }
        let Some(query) = &self.certificate_query else {
            return;
        };
        let result = match query.receiver.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(text(self.language, T::CertificateCheckFailed).into())
            }
        };
        let query = self.certificate_query.take().unwrap();
        match result {
            Ok(report) if report.verification_errors.is_empty() => {
                self.certificate_approval = Some(CertificateApproval {
                    target: query.target,
                    certificate_sha256: None,
                });
                self.connect();
            }
            Ok(report) => {
                self.certificate_review = Some(CertificateReview {
                    target: query.target,
                    report,
                    remember: false,
                });
                self.show(ctx);
            }
            Err(error) => {
                self.notice = Some(Notice::error(T::CertificateCheckFailed, error));
                self.show(ctx);
            }
        }
    }

    fn approve_certificate(&mut self, review: &CertificateReview) -> Result<()> {
        let approval = CertificateApproval {
            target: review.target.clone(),
            certificate_sha256: Some(review.report.certificate_sha256.clone()),
        };
        let connection = approval
            .connection_profile(self.profiles.selected_id, &self.profile)
            .context("Certificate decision no longer matches the connection profile")?;
        if review.remember {
            let previous = std::mem::replace(
                &mut self.profile.certificate_sha256,
                connection.certificate_sha256,
            );
            if let Err(error) = self.save() {
                self.profile.certificate_sha256 = previous;
                return Err(error);
            }
            self.certificate_approval = None;
        } else {
            self.certificate_approval = Some(approval);
        }
        Ok(())
    }

    fn certificate_dialogs(&mut self, ctx: &egui::Context) {
        if let Some(query) = &self.certificate_query {
            if certificate_ui::checking(
                ctx,
                self.language,
                &self.profile.name,
                &query.target.endpoint(),
            ) {
                self.clear_certificate_check();
            }
        } else if let Some(review) = &mut self.certificate_review {
            let choice = certificate_ui::review(
                ctx,
                self.language,
                &self.profile.name,
                &review.target.endpoint(),
                &review.report,
                &mut review.remember,
            );
            if let Some(choice) = choice {
                let review = self.certificate_review.take().unwrap();
                if matches!(choice, CertificateChoice::Continue)
                    && review.target
                        == CertificateTarget::new(self.profiles.selected_id, &self.profile)
                {
                    match self.approve_certificate(&review) {
                        Ok(()) => self.connect(),
                        Err(error) => {
                            self.certificate_approval = None;
                            self.notice = Some(Notice::error(T::CertificateDecisionFailed, error));
                        }
                    }
                } else {
                    self.certificate_approval = None;
                }
            }
        }
    }

    fn show(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn hide(&mut self, ctx: &egui::Context) {
        if self.tray.is_some() {
            self.hidden = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn quit(&mut self, ctx: &egui::Context) {
        self.clear_certificate_check();
        self.password.zeroize();
        self.otp.zeroize();
        self.controller.shutdown();
        self.quitting = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let lang = self.language;
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            logo(ui, 30.0, colors.blue);
            ui.label(
                RichText::new("SSLRay")
                    .size(23.0)
                    .strong()
                    .color(colors.ink),
            );
        });
        ui.add_space(5.0);
        ui.label(
            RichText::new(text(lang, T::Tagline))
                .size(12.0)
                .color(colors.muted),
        );
        ui.add_space(36.0);
        for (page, name) in [
            (Page::Overview, text(lang, T::Overview)),
            (Page::Settings, text(lang, T::Settings)),
            (Page::Logs, text(lang, T::Logs)),
            (Page::AppSettings, text(lang, T::AppSettings)),
        ] {
            let selected = self.page == page;
            let text = RichText::new(name).size(14.0).color(if selected {
                colors.blue
            } else {
                colors.muted
            });
            let button = egui::Button::new(text)
                .fill(if selected {
                    colors.pale
                } else {
                    Color32::TRANSPARENT
                })
                .corner_radius(8)
                .min_size(Vec2::new(164.0, 43.0));
            if ui.add(button).clicked() {
                self.page = page;
            }
            ui.add_space(7.0);
        }
        ui.with_layout(egui::Layout::bottom_up(Align::LEFT), |ui| {
            ui.label(
                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .size(12.0)
                    .color(colors.muted),
            );
            ui.add_space(16.0);
            if self.tray.is_some()
                && ui
                    .add(
                        egui::Button::new(
                            RichText::new(text(lang, T::HideToTray)).color(colors.muted),
                        )
                        .frame(false),
                    )
                    .clicked()
            {
                self.hide(ui.ctx());
            }
            ui.add_space(9.0);
            ui.separator();
            ui.add_space(13.0);
            ui.label(
                RichText::new(text(lang, T::DesktopClient))
                    .size(12.0)
                    .color(colors.muted),
            );
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        self.profile_selector(ui, false);
        let lang = self.language;
        if self.authorization_retry && !self.busy() {
            card(ui).show(ui, |ui| {
                ui.label(
                    RichText::new(text(lang, T::AuthorizationFailed))
                        .strong()
                        .color(colors.warning),
                );
                ui.label(text(lang, T::AuthorizationRetryHelp));
                ui.label(text(lang, self.authorization_help()));
                if ui.button(text(lang, T::RetryAuthorization)).clicked() {
                    self.connect();
                }
            });
            ui.add_space(16.0);
        }
        let state = &self.controller.snapshot().state;
        let connected = *state == ConnectionState::Connected;
        let connecting = matches!(
            state,
            ConnectionState::Connecting
                | ConnectionState::AwaitingOtp
                | ConnectionState::Disconnecting
        );
        let (status, color) = match state {
            ConnectionState::Connected => (text(lang, T::Connected), colors.green),
            ConnectionState::Connecting => (text(lang, T::Connecting), colors.blue),
            ConnectionState::AwaitingOtp => (text(lang, T::AwaitingOtp), colors.blue),
            ConnectionState::Disconnecting => (text(lang, T::Disconnecting), colors.muted),
            ConnectionState::Failed => (text(lang, T::Failed), colors.danger),
            ConnectionState::Disconnected => (text(lang, T::Ready), colors.blue),
        };
        card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(84.0), egui::Sense::hover());
                let painter = ui.painter();
                painter.circle_filled(rect.center(), 40.0, color.gamma_multiply(0.08));
                painter.circle_stroke(
                    rect.center(),
                    30.0,
                    Stroke::new(1.5, color.gamma_multiply(0.22)),
                );
                let center = rect.center();
                let points = vec![
                    center + Vec2::new(0.0, -17.0),
                    center + Vec2::new(14.0, -10.0),
                    center + Vec2::new(12.0, 7.0),
                    center + Vec2::new(0.0, 18.0),
                    center + Vec2::new(-12.0, 7.0),
                    center + Vec2::new(-14.0, -10.0),
                ];
                painter.add(egui::Shape::convex_polygon(points, color, Stroke::NONE));
                painter.line_segment(
                    [center + Vec2::new(-6.0, 0.0), center + Vec2::new(-1.0, 5.0)],
                    Stroke::new(2.0, Color32::WHITE),
                );
                painter.line_segment(
                    [center + Vec2::new(-1.0, 5.0), center + Vec2::new(7.0, -5.0)],
                    Stroke::new(2.0, Color32::WHITE),
                );
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.add_space(12.0);
                    ui.label(RichText::new(status).size(23.0).strong().color(colors.ink));
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(if connected {
                            text(lang, T::TunnelEstablished)
                        } else {
                            text(lang, T::TunnelDescription)
                        })
                        .size(12.0)
                        .color(colors.muted),
                    );
                    ui.add_space(5.0);
                    ui.label(
                        RichText::new(if self.profile.protocol == VpnProtocol::OpenVpn {
                            std::path::Path::new(&self.profile.openvpn_config)
                                .file_name()
                                .map(|name| name.to_string_lossy().into_owned())
                                .filter(|name| !name.is_empty())
                                .unwrap_or_else(|| text(lang, T::OvpnPathRequired).into())
                        } else {
                            format!("{}:{}", self.profile.host, self.profile.port)
                        })
                        .size(12.0)
                        .color(colors.muted),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let text = if connected {
                        text(lang, T::Disconnect)
                    } else if connecting {
                        text(lang, T::CancelConnect)
                    } else {
                        text(lang, T::Connect)
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(text).color(Color32::WHITE).size(14.0))
                                .fill(colors.blue)
                                .corner_radius(9)
                                .min_size(Vec2::new(140.0, 44.0)),
                        )
                        .clicked()
                    {
                        if connected || connecting {
                            self.controller.disconnect();
                        } else {
                            self.connect();
                        }
                    }
                });
            });
            let message = self.controller.snapshot().message.clone();
            if !message.is_empty() {
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(10.0);
                ui.label(
                    RichText::new(i18n::diagnostic(lang, &message))
                        .size(12.0)
                        .color(colors.muted),
                );
            }
        });
        ui.add_space(17.0);
        let snapshot = self.controller.snapshot();
        let address = snapshot.address.as_deref().unwrap_or("—").to_owned();
        let interface = snapshot.interface.as_deref().unwrap_or("—").to_owned();
        let tx = bytes(snapshot.tx_bytes);
        let rx = bytes(snapshot.rx_bytes);
        ui.columns(3, |cols| {
            metric(
                &mut cols[0],
                text(lang, T::VirtualIp),
                &address,
                &format!("{}  {interface}", text(lang, T::Interface)),
            );
            metric(
                &mut cols[1],
                text(lang, T::Upload),
                &tx,
                text(lang, T::SentEncrypted),
            );
            metric(
                &mut cols[2],
                text(lang, T::Download),
                &rx,
                &format!(
                    "{}  {}",
                    text(lang, T::ConnectedTime),
                    duration(snapshot.elapsed_secs)
                ),
            );
        });
        ui.add_space(18.0);
        ui.horizontal_wrapped(|ui| {
            badge(ui, text(lang, protocol_label(self.profile.protocol)));
            badge(
                ui,
                text(
                    lang,
                    transport_badge_label(self.profile.protocol, self.profile.transport),
                ),
            );
            badge(ui, text(lang, route_policy_label(self.profile.route_mode)));
            badge(
                ui,
                match self.profile.crypto {
                    CryptoMode::Standard => text(lang, T::StandardCrypto),
                    CryptoMode::GmTls13 => text(lang, T::GmTls13),
                },
            );
            if let Some(transport) = &self.controller.snapshot().transport {
                badge(
                    ui,
                    &format!("{} · {transport}", text(lang, T::ActualTransport)),
                );
            }
            if let Some(cipher) = &self.controller.snapshot().cipher {
                ui.label(RichText::new(cipher).size(12.0).color(colors.muted));
            }
        });
    }

    fn credentials(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let lang = self.language;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(text(lang, T::Credentials))
                    .size(16.0)
                    .strong()
                    .color(colors.ink),
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(text(
                        lang,
                        if self.remember_password {
                            T::RememberPassword
                        } else {
                            T::PasswordSessionOnly
                        },
                    ))
                    .size(12.0)
                    .color(colors.muted),
                );
            });
        });
        ui.add_space(9.0);
        let busy = self.busy();
        card(ui).show(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                if self.profile.protocol == VpnProtocol::OpenVpn {
                    ui.label(
                        RichText::new(text(lang, T::OvpnCredentialsHelp))
                            .size(12.0)
                            .color(colors.muted),
                    );
                    ui.add_space(9.0);
                }
                ui.columns(2, |cols| {
                    field_label(&mut cols[0], text(lang, T::Username));
                    cols[0].add(
                        egui::TextEdit::singleline(&mut self.profile.username)
                            .desired_width(f32::INFINITY)
                            .hint_text(text(lang, T::UsernameHint))
                            .margin(Vec2::new(10.0, 10.0)),
                    );
                    field_label(&mut cols[1], text(lang, T::Password));
                    password_edit(
                        &mut cols[1],
                        &mut self.password,
                        &mut self.show_password,
                        lang,
                        egui::Margin::symmetric(10, 10),
                    );
                    cols[1].add_space(7.0);
                    self.password_storage_option(&mut cols[1]);
                });
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(7.0);
                ui.checkbox(&mut self.use_otp, text(lang, T::UseOtp));
                ui.label(
                    RichText::new(text(lang, T::OtpPrivacy))
                        .size(12.0)
                        .color(colors.muted),
                );
                if self.use_otp {
                    ui.add_space(8.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.otp)
                            .password(true)
                            .desired_width(250.0)
                            .hint_text(text(lang, T::OtpHint))
                            .margin(Vec2::new(10.0, 8.0)),
                    );
                    ui.label(
                        RichText::new(text(lang, T::OtpSeparate))
                            .size(12.0)
                            .color(colors.muted),
                    );
                }
            });
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        self.profile_selector(ui, true);
        let lang = self.language;
        let previous_endpoint = (
            self.profile.protocol,
            self.profile.host.clone(),
            self.profile.port,
            self.profile.openvpn_config.clone(),
            self.profile.username.clone(),
        );
        let previous_certificate_endpoint = (
            self.profile.protocol,
            self.profile.host.clone(),
            self.profile.port,
            self.profile.crypto,
        );
        let action_size = Vec2::new(100.0, 32.0);
        action_row(ui, |ui| {
            ui.label(
                RichText::new(text(lang, T::ConnectionProfile))
                    .size(16.0)
                    .strong(),
            );
            if ui
                .add_enabled(
                    !self.busy(),
                    egui::Button::new(text(lang, T::SaveProfile))
                        .corner_radius(7)
                        .min_size(action_size),
                )
                .clicked()
            {
                self.notice = Some(match self.save() {
                    Ok(()) => Notice::plain(T::ProfileSaved),
                    Err(error) => Notice::error(T::SaveFailed, format!("{error:#}")),
                });
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    !self.busy(),
                    egui::Button::new(RichText::new(text(lang, T::Connect)).color(Color32::WHITE))
                        .fill(colors.blue)
                        .corner_radius(7)
                        .min_size(action_size),
                )
                .clicked()
            {
                self.connect();
            }
        });
        ui.add_space(12.0);
        let busy = self.busy();
        ui.add_enabled_ui(!busy, |ui| {
            card(ui).show(ui, |ui| {
                field_label(ui, text(lang, T::ProfileName));
                ui.add(
                    egui::TextEdit::singleline(&mut self.profile.name)
                        .desired_width(f32::INFINITY)
                        .margin(Vec2::splat(9.0)),
                );
                ui.add_space(14.0);
                field_label(ui, text(lang, T::Protocol));
                let previous_protocol = self.profile.protocol;
                egui::ComboBox::from_id_salt("vpn-protocol")
                    .width(ui.available_width())
                    .selected_text(text(lang, protocol_label(self.profile.protocol)))
                    .show_ui(ui, |ui| {
                        for protocol in [
                            VpnProtocol::Huawei,
                            VpnProtocol::Cisco,
                            VpnProtocol::OpenVpn,
                        ] {
                            ui.selectable_value(
                                &mut self.profile.protocol,
                                protocol,
                                text(lang, protocol_label(protocol)),
                            );
                        }
                    });
                if self.profile.protocol != previous_protocol {
                    self.password.zeroize();
                    self.otp.zeroize();
                    self.use_otp = false;
                    self.show_password = false;
                    self.notice = None;
                }
                ui.add_space(14.0);
                let protocol = self.profile.protocol;
                if protocol == VpnProtocol::OpenVpn {
                    field_label(ui, text(lang, T::OvpnConfig));
                    ui.horizontal(|ui| {
                        let input_width = (ui.available_width() - 120.0).max(160.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.profile.openvpn_config)
                                .desired_width(input_width)
                                .hint_text(text(lang, T::OvpnPathHint))
                                .margin(Vec2::splat(9.0)),
                        );
                        if ui.button(text(lang, T::Browse)).clicked() {
                            let mut dialog = rfd::FileDialog::new()
                                .set_title(text(lang, T::OvpnDialogTitle))
                                .add_filter("OpenVPN", &["ovpn"]);
                            if let Some(directory) =
                                std::path::Path::new(&self.profile.openvpn_config)
                                    .parent()
                                    .filter(|directory| directory.is_dir())
                            {
                                dialog = dialog.set_directory(directory);
                            }
                            if let Some(path) = dialog.pick_file() {
                                self.profile.openvpn_config = path.to_string_lossy().into_owned();
                            }
                        }
                    });
                    ui.add_space(7.0);
                    ui.label(
                        RichText::new(text(lang, T::OvpnConfigHelp))
                            .size(12.0)
                            .color(colors.muted),
                    );
                } else {
                    ui.columns(2, |cols| {
                        field_label(&mut cols[0], text(lang, T::GatewayHost));
                        cols[0].add(
                            egui::TextEdit::singleline(&mut self.profile.host)
                                .desired_width(f32::INFINITY)
                                .margin(Vec2::splat(9.0)),
                        );
                        field_label(&mut cols[1], text(lang, T::Port));
                        cols[1].add(
                            egui::DragValue::new(&mut self.profile.port)
                                .range(1..=65535)
                                .speed(1.0),
                        );
                    });
                }
                ui.add_space(14.0);
                ui.columns(2, |cols| {
                    field_label(&mut cols[0], text(lang, T::Transport));
                    egui::ComboBox::from_id_salt("transport")
                        .width(230.0)
                        .selected_text(text(
                            lang,
                            transport_label(protocol, self.profile.transport),
                        ))
                        .show_ui(&mut cols[0], |ui| {
                            for transport in [TransportMode::Auto, TransportMode::Tls] {
                                ui.selectable_value(
                                    &mut self.profile.transport,
                                    transport,
                                    text(lang, transport_label(protocol, transport)),
                                );
                            }
                            ui.add_enabled_ui(protocol != VpnProtocol::Cisco, |ui| {
                                ui.selectable_value(
                                    &mut self.profile.transport,
                                    TransportMode::Udp,
                                    text(lang, transport_label(protocol, TransportMode::Udp)),
                                );
                            })
                            .response
                            .on_hover_text(text(
                                lang,
                                if protocol == VpnProtocol::Cisco {
                                    T::CiscoTransportHelp
                                } else if protocol == VpnProtocol::Huawei {
                                    T::UdpTooltip
                                } else {
                                    T::OvpnTransportHelp
                                },
                            ));
                        });
                    field_label(&mut cols[1], text(lang, T::CryptoPolicy));
                    egui::ComboBox::from_id_salt("crypto")
                        .width(230.0)
                        .selected_text(text(
                            lang,
                            match self.profile.crypto {
                                CryptoMode::Standard => T::StandardTls,
                                CryptoMode::GmTls13 => T::GmOption,
                            },
                        ))
                        .show_ui(&mut cols[1], |ui| {
                            ui.selectable_value(
                                &mut self.profile.crypto,
                                CryptoMode::Standard,
                                text(lang, T::StandardTls),
                            );
                            ui.add_enabled_ui(
                                self.gm_available && protocol != VpnProtocol::OpenVpn,
                                |ui| {
                                    ui.selectable_value(
                                        &mut self.profile.crypto,
                                        CryptoMode::GmTls13,
                                        text(lang, T::GmOption),
                                    );
                                },
                            )
                            .response
                            .on_hover_text(text(
                                lang,
                                if protocol == VpnProtocol::OpenVpn {
                                    T::OvpnGmUnsupported
                                } else {
                                    T::GmTooltip
                                },
                            ));
                        });
                });
                if protocol == VpnProtocol::Huawei {
                    ui.add_space(12.0);
                    ui.checkbox(
                        &mut self.profile.allow_legacy_udp,
                        text(lang, T::AllowLegacyUdp),
                    )
                    .on_hover_text(text(lang, T::LegacyUdpTooltip));
                    if self.profile.allow_legacy_udp {
                        ui.add_space(7.0);
                        egui::Frame::new()
                            .fill(colors.warning_bg)
                            .corner_radius(7)
                            .inner_margin(10.0)
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(text(lang, T::LegacyUdpWarning))
                                        .size(12.0)
                                        .color(colors.warning),
                                );
                            });
                    }
                }
                ui.add_space(10.0);
                ui.label(
                    RichText::new(text(
                        lang,
                        match protocol {
                            VpnProtocol::Huawei => T::TransportCryptoHelp,
                            VpnProtocol::Cisco => T::CiscoTransportHelp,
                            VpnProtocol::OpenVpn => T::OvpnTransportHelp,
                        },
                    ))
                    .size(12.0)
                    .color(colors.muted),
                );
                ui.add_space(5.0);
                if protocol == VpnProtocol::OpenVpn {
                    ui.label(
                        RichText::new(text(lang, T::OvpnGmUnsupported))
                            .size(12.0)
                            .color(if self.profile.crypto == CryptoMode::GmTls13 {
                                colors.danger
                            } else {
                                colors.muted
                            }),
                    );
                } else {
                    ui.label(
                        RichText::new(format!(
                            "{}: {}  ·  {} {}",
                            text(lang, T::CryptoBackend),
                            self.crypto_backend,
                            text(lang, T::GmTls13),
                            text(
                                lang,
                                if self.gm_available {
                                    T::Available
                                } else {
                                    T::Unavailable
                                }
                            )
                        ))
                        .size(12.0)
                        .color(colors.muted),
                    );
                }
            });
            ui.add_space(16.0);
            self.credentials(ui);
            ui.add_space(16.0);
            card(ui).show(ui, |ui| {
                ui.label(
                    RichText::new(text(lang, T::CertificateTrust))
                        .size(14.0)
                        .strong(),
                );
                ui.add_space(5.0);
                ui.label(
                    RichText::new(text(
                        lang,
                        if self.profile.protocol == VpnProtocol::OpenVpn {
                            T::OvpnCertificateHelp
                        } else {
                            T::CertificateHelp
                        },
                    ))
                    .size(12.0)
                    .color(colors.muted),
                );
                ui.add_space(9.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.profile.certificate_sha256)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .hint_text(text(lang, T::FingerprintHint))
                        .margin(Vec2::splat(9.0)),
                );
            });
            ui.add_space(16.0);
            card(ui).show(ui, |ui| {
                action_row(ui, |ui| {
                    ui.label(RichText::new(text(lang, T::Routing)).size(14.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        ui.label("MTU");
                        ui.add(egui::DragValue::new(&mut self.profile.mtu).range(576..=1500));
                    });
                });
                ui.add_space(9.0);
                field_label(ui, text(lang, T::RoutePolicy));
                egui::ComboBox::from_id_salt("route-policy")
                    .width(ui.available_width())
                    .selected_text(text(lang, route_policy_label(self.profile.route_mode)))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.profile.route_mode,
                            RouteMode::GatewayOnly,
                            text(lang, T::RouteGatewayOnly),
                        );
                        ui.selectable_value(
                            &mut self.profile.route_mode,
                            RouteMode::Merge,
                            text(lang, T::RouteMerge),
                        );
                        ui.selectable_value(
                            &mut self.profile.route_mode,
                            RouteMode::ManualOnly,
                            text(lang, T::RouteManual),
                        );
                        ui.selectable_value(
                            &mut self.profile.route_mode,
                            RouteMode::FullTunnel,
                            text(lang, T::RouteFull),
                        );
                    });
                ui.add_space(9.0);
                if self.profile.route_mode == RouteMode::GatewayOnly {
                    ui.label(
                        RichText::new(text(lang, T::GatewayRoutesHelp))
                            .size(12.0)
                            .color(colors.muted),
                    );
                } else if self.profile.route_mode == RouteMode::FullTunnel {
                    ui.label(
                        RichText::new(text(lang, T::FullTunnelHelp))
                            .size(12.0)
                            .color(colors.muted),
                    );
                } else {
                    ui.label(
                        RichText::new(text(lang, T::RouteSafetyHelp))
                            .size(12.0)
                            .color(colors.muted),
                    );
                }
                ui.add_space(12.0);
                field_label(ui, text(lang, T::ManualRoutes));
                ui.label(
                    RichText::new(text(lang, T::ManualRoutesHelp))
                        .size(12.0)
                        .color(colors.muted),
                );
                if self.profile.route_mode == RouteMode::ManualOnly
                    && self.route_text.trim().is_empty()
                {
                    ui.label(
                        RichText::new(text(lang, T::NoManualRoutes))
                            .size(12.0)
                            .color(colors.warning),
                    );
                }
                ui.add_space(8.0);
                let manual_active = matches!(
                    self.profile.route_mode,
                    RouteMode::Merge | RouteMode::ManualOnly
                );
                if !manual_active {
                    ui.label(
                        RichText::new(text(lang, T::ManualRoutesInactive))
                            .size(12.0)
                            .color(colors.muted),
                    );
                }
                ui.add_enabled(
                    manual_active,
                    egui::TextEdit::multiline(&mut self.route_text)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3)
                        .margin(Vec2::splat(9.0)),
                );
            });
        });
        ui.add_space(16.0);
        card(ui).show(ui, |ui| {
            let snapshot = self.controller.snapshot();
            let connected = snapshot.state == ConnectionState::Connected;
            for (title, routes, empty) in [
                (
                    T::AdvertisedRoutes,
                    &snapshot.advertised_routes,
                    T::NoAdvertisedRoutes,
                ),
                (
                    T::AppliedRoutes,
                    &snapshot.applied_routes,
                    T::NoAppliedRoutes,
                ),
            ] {
                ui.label(
                    RichText::new(format!("{} ({})", text(lang, title), routes.len()))
                        .size(13.0)
                        .strong(),
                );
                ui.add_space(5.0);
                if routes.is_empty() {
                    ui.label(
                        RichText::new(text(
                            lang,
                            if connected {
                                empty
                            } else {
                                T::RoutesAfterConnect
                            },
                        ))
                        .size(12.0)
                        .color(colors.muted),
                    );
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt(format!("routes-{title:?}"))
                        .max_height(115.0)
                        .show(ui, |ui| {
                            for route in routes {
                                ui.add(
                                    egui::Label::new(RichText::new(route).monospace())
                                        .selectable(true),
                                );
                            }
                        });
                }
                ui.add_space(12.0);
            }
        });
        if busy {
            ui.add_space(10.0);
            ui.label(RichText::new(text(lang, T::DisconnectToEdit)).color(colors.muted));
        }
        if previous_certificate_endpoint
            != (
                self.profile.protocol,
                self.profile.host.clone(),
                self.profile.port,
                self.profile.crypto,
            )
        {
            self.clear_certificate_check();
            self.profile.certificate_sha256.clear();
        }
        if previous_endpoint
            != (
                self.profile.protocol,
                self.profile.host.clone(),
                self.profile.port,
                self.profile.openvpn_config.clone(),
                self.profile.username.clone(),
            )
        {
            self.password.zeroize();
            self.otp.zeroize();
            self.remember_password = false;
            self.use_otp = false;
            self.show_password = false;
            self.pending_password = None;
            self.pending_otp = None;
            self.authorization_retry = false;
        }
    }

    fn logs(&mut self, ui: &mut egui::Ui) {
        let colors = palette(ui);
        let lang = self.language;
        action_row(ui, |ui| {
            ui.label(
                RichText::new(text(lang, T::SessionEvents))
                    .size(16.0)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if ui.button(text(lang, T::CopyLogs)).clicked() {
                    ui.ctx().copy_text(
                        self.controller
                            .snapshot()
                            .logs
                            .iter()
                            .map(|line| i18n::diagnostic(lang, line))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
            });
        });
        ui.add_space(8.0);
        ui.label(
            RichText::new(text(lang, T::LogsHelp))
                .size(12.0)
                .color(colors.muted),
        );
        ui.add_space(14.0);
        card(ui).show(ui, |ui| {
            ui.set_min_height(410.0);
            let logs = &self.controller.snapshot().logs;
            if logs.is_empty() {
                ui.add_space(135.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(text(lang, T::NoEvents))
                            .size(17.0)
                            .color(colors.muted),
                    );
                    ui.add_space(8.0);
                    ui.label(RichText::new(text(lang, T::EventsAfterConnect)).color(colors.muted));
                });
            } else {
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .max_height(500.0)
                    .show(ui, |ui| {
                        for line in logs {
                            ui.label(
                                RichText::new(i18n::diagnostic(lang, line))
                                    .font(FontId::monospace(11.0))
                                    .color(colors.ink),
                            );
                            ui.add_space(5.0);
                        }
                    });
            }
        });
    }

    fn refresh_adapter(&mut self, ctx: &egui::Context) {
        if self.adapter_query.is_some() {
            return;
        }
        let Some(request) = self.adapter_display.refresh() else {
            return;
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        self.adapter_query = Some(receiver);
        let context = ctx.clone();
        std::thread::spawn(move || {
            let result =
                system_info::adapter(&request.target.name).map_err(|error| error.to_string());
            let _ = sender.send(AdapterResponse { request, result });
            context.request_repaint();
        });
    }

    fn sync_adapter(&mut self, ctx: &egui::Context) {
        let target =
            AdapterTarget::from_snapshot(self.controller.snapshot(), self.busy(), self.profile.mtu);
        if self.adapter_display.select(target) {
            // Dropping the old receiver prevents results from a disconnected
            // session from being routed into a new query, even with the same name.
            self.adapter_query = None;
            self.refresh_adapter(ctx);
        }
        let result = self
            .adapter_query
            .as_ref()
            .map(|receiver| receiver.try_recv());
        match result {
            Some(Ok(response)) => {
                self.adapter_query = None;
                self.adapter_display.accept(response);
            }
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                self.adapter_query = None;
                self.adapter_display.error = Some(text(self.language, T::AdapterReadFailed).into());
            }
            _ => {}
        }
    }

    fn authorization_help(&self) -> T {
        if cfg!(target_os = "windows") {
            T::AuthorizationWindowsHelp
        } else if cfg!(target_os = "linux") {
            T::AuthorizationLinuxHelp
        } else {
            T::AuthorizationMacHelp
        }
    }

    fn application_settings(&mut self, ui: &mut egui::Ui) {
        let lang = self.language;
        let colors = palette(ui);
        self.sync_adapter(ui.ctx());
        card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new(text(lang, T::Appearance)).size(16.0).strong());
            ui.add_space(14.0);
            ui.columns(2, |columns| {
                self.language_selector(&mut columns[0]);
                self.theme_selector(&mut columns[1]);
            });
        });
        ui.add_space(16.0);
        card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            action_row(ui, |ui| {
                ui.label(
                    RichText::new(text(lang, T::AdapterInfo))
                        .size(16.0)
                        .strong(),
                );
                if ui
                    .add_enabled(
                        self.adapter_display.target.is_some() && self.adapter_query.is_none(),
                        egui::Button::new(text(lang, T::Refresh)),
                    )
                    .clicked()
                {
                    self.refresh_adapter(ui.ctx());
                }
            });
            ui.add_space(10.0);
            if self.adapter_query.is_some() {
                ui.label(text(lang, T::Loading));
            }
            if let Some(error) = &self.adapter_display.error {
                ui.label(
                    RichText::new(format!("{}: {error}", text(lang, T::AdapterReadFailed)))
                        .color(colors.warning),
                );
            }
            if let Some(target) = &self.adapter_display.target {
                let metadata = self.adapter_display.metadata.as_ref();
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("{}: {}", text(lang, T::AdapterName), target.name))
                            .strong(),
                    );
                    if let Some(adapter) = metadata {
                        badge(
                            ui,
                            text(
                                lang,
                                if adapter.is_up {
                                    T::AdapterUp
                                } else {
                                    T::AdapterDown
                                },
                            ),
                        );
                        if adapter.virtual_interface {
                            badge(ui, text(lang, T::TunnelAdapter));
                        }
                        if let Some(mtu) = adapter.mtu {
                            ui.label(format!("MTU {mtu}"));
                        }
                    }
                });
                if let Some(adapter) = metadata {
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            text(lang, T::AdapterAddresses),
                            if adapter.addresses.is_empty() {
                                "—".into()
                            } else {
                                adapter.addresses.join("  ·  ")
                            }
                        ))
                        .monospace()
                        .size(12.0)
                        .color(colors.muted),
                    );
                } else {
                    // Only known values from this session are shown on lookup
                    // failure; never replace them with another local interface.
                    ui.label(
                        RichText::new(text(lang, T::AdapterSnapshotOnly))
                            .size(12.0)
                            .color(colors.muted),
                    );
                    ui.label(format!(
                        "{}: {}",
                        text(lang, T::AdapterAddresses),
                        target.address.as_deref().unwrap_or("—")
                    ));
                    ui.label(format!(
                        "{}: {}",
                        text(lang, T::ConfiguredMtu),
                        target.configured_mtu
                    ));
                }
            } else {
                ui.label(text(lang, T::NoAdapters));
                if !self.controller.snapshot().applied_routes.is_empty() {
                    ui.label(
                        RichText::new(text(lang, T::AdapterCleanupUnconfirmed))
                            .size(12.0)
                            .color(colors.warning),
                    );
                }
            }
        });
        ui.add_space(16.0);
        card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new(text(lang, T::Authorization))
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(8.0);
            ui.label(text(lang, self.authorization_help()));
            ui.label(text(lang, T::AuthorizationRetryHelp));
        });
        ui.add_space(16.0);
        card(ui).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new(text(lang, T::About)).size(16.0).strong());
            ui.add_space(10.0);
            ui.label(format!(
                "{}: {}",
                text(lang, T::Version),
                env!("CARGO_PKG_VERSION")
            ));
            ui.label(format!(
                "{}: {} / {}",
                text(lang, T::Platform),
                std::env::consts::OS,
                std::env::consts::ARCH
            ));
            ui.label(format!(
                "{}: {}",
                text(lang, T::CryptoBackend),
                self.crypto_backend
            ));
        });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.controller.poll();
        self.poll_certificate_check(ctx);
        if self.controller.snapshot().state == ConnectionState::Connected {
            self.pending_password = None;
            self.pending_otp = None;
        } else if !self.busy() && (self.pending_password.is_some() || self.pending_otp.is_some()) {
            if self.controller.snapshot().authorization_failed {
                if let Some(password) = self.pending_password.take() {
                    self.password = password.to_string();
                }
                if let Some(otp) = self.pending_otp.take() {
                    self.otp = otp.to_string();
                }
                self.authorization_retry = true;
            } else {
                self.pending_password = None;
                self.pending_otp = None;
            }
        }
        self.sync_adapter(ctx);
        if self.controller.snapshot().credentials_rejected
            && !self.rejection_handled
            && !self.busy()
        {
            self.rejection_handled = true;
            self.password.zeroize();
            self.otp.zeroize();
            self.remember_password = false;
            let mut candidate = self.profiles.clone();
            let had_saved_password = candidate.selected().saved_password.is_some();
            let result = candidate.set_saved_password(None).and_then(|()| {
                if had_saved_password {
                    self.persist_library(&candidate)
                } else {
                    Ok(())
                }
            });
            self.profiles = candidate;
            self.notice = Some(match result {
                Ok(()) if had_saved_password => Notice {
                    title: T::PasswordRejected,
                    detail: Some(text(self.language, T::SavedPasswordRemoved).into()),
                },
                Ok(()) => Notice::plain(T::PasswordRejected),
                Err(error) => Notice::error(T::SaveFailed, error),
            });
            self.password_dialog = true;
            self.show(ctx);
        }
        if self.controller.snapshot().state == ConnectionState::AwaitingOtp {
            if !self.challenge_prompted {
                self.otp.zeroize();
                self.challenge_prompted = true;
                self.challenge_focus = true;
                self.show(ctx);
            }
        } else {
            self.challenge_prompted = false;
        }
        let actions: Vec<_> = self
            .tray
            .as_ref()
            .map(|tray| tray.actions.try_iter().collect())
            .unwrap_or_default();
        for action in actions {
            match action {
                tray::Action::Show => self.show(ctx),
                tray::Action::Hide => self.hide(ctx),
                tray::Action::Disconnect => {
                    self.clear_certificate_check();
                    self.controller.disconnect();
                }
                tray::Action::Quit => self.quit(ctx),
            }
        }
        if ctx.input(|input| input.viewport().close_requested()) && !self.quitting {
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.hide(ctx);
            } else {
                self.clear_certificate_check();
                self.controller.disconnect();
            }
        }
        // egui 0.35 calls logic while hidden, so background status and tray events remain live.
        ctx.request_repaint_after(Duration::from_millis(
            if self.busy() || self.certificate_query.is_some() {
                200
            } else {
                800
            },
        ));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let colors = palette(ui);
        let lang = self.language;
        egui::Panel::left("sidebar")
            .exact_size(205.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(colors.surface)
                    .inner_margin(20.0)
                    .stroke(Stroke::new(1.0, colors.line)),
            )
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(colors.background)
                    .inner_margin(28.0),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(match self.page {
                                Page::Overview => text(lang, T::Overview),
                                Page::Settings => text(lang, T::Settings),
                                Page::Logs => text(lang, T::Logs),
                                Page::AppSettings => text(lang, T::AppSettings),
                            })
                            .size(26.0)
                            .strong()
                            .color(colors.ink),
                        );
                        ui.add_space(5.0);
                        ui.label(
                            RichText::new(match self.page {
                                Page::Overview => text(lang, T::OverviewSubtitle),
                                Page::Settings => text(lang, T::SettingsSubtitle),
                                Page::Logs => text(lang, T::LogsSubtitle),
                                Page::AppSettings => text(lang, T::AppSettingsSubtitle),
                            })
                            .size(12.0)
                            .color(colors.muted),
                        );
                    });
                });
                ui.add_space(23.0);
                if let Some(notice) = self.notice.as_ref().map(|notice| notice.display(lang)) {
                    egui::Frame::new()
                        .fill(colors.pale)
                        .corner_radius(8)
                        .inner_margin(11.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(notice).size(12.0).color(colors.ink));
                                if ui.small_button("×").clicked() {
                                    self.notice = None;
                                }
                            });
                        });
                    ui.add_space(14.0);
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        Page::Overview => self.overview(ui),
                        Page::Settings => self.settings(ui),
                        Page::Logs => self.logs(ui),
                        Page::AppSettings => self.application_settings(ui),
                    });
            });
        self.profile_dialogs(ui.ctx());
        self.credential_dialogs(ui.ctx());
        self.certificate_dialogs(ui.ctx());
        if self.controller.snapshot().state == ConnectionState::AwaitingOtp {
            let challenge = self
                .controller
                .snapshot()
                .challenge
                .clone()
                .unwrap_or_else(|| text(lang, T::OtpChallenge).into());
            let response =
                egui::Modal::new(egui::Id::new("second-password-challenge")).show(ui.ctx(), |ui| {
                    ui.set_width(380.0);
                    ui.label(RichText::new(text(lang, T::OtpTitle)).size(20.0).strong());
                    ui.add_space(9.0);
                    ui.label(RichText::new(challenge).size(12.0).color(colors.muted));
                    ui.add_space(14.0);
                    let input = ui.add(
                        egui::TextEdit::singleline(&mut self.otp)
                            .password(true)
                            .desired_width(f32::INFINITY)
                            .hint_text(text(lang, T::OtpChallengeHint))
                            .margin(Vec2::splat(10.0)),
                    );
                    if self.challenge_focus {
                        input.request_focus();
                        self.challenge_focus = false;
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(text(lang, T::OtpPrivacy))
                            .size(12.0)
                            .color(colors.muted),
                    );
                    if let Some(notice) = &self.notice {
                        ui.label(
                            RichText::new(notice.display(lang))
                                .size(12.0)
                                .color(colors.danger),
                        );
                    }
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.button(text(lang, T::CancelConnect)).clicked() {
                            self.otp.zeroize();
                            self.controller.disconnect();
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            let submit = ui
                                .add_enabled(
                                    !self.otp.trim().is_empty(),
                                    egui::Button::new(
                                        RichText::new(text(lang, T::SubmitOtp))
                                            .color(Color32::WHITE),
                                    )
                                    .fill(colors.blue),
                                )
                                .clicked()
                                || (input.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    && !self.otp.trim().is_empty());
                            if submit {
                                let mut otp = std::mem::take(&mut self.otp);
                                if otp.is_empty() || otp.len() > 31 || otp.contains('\0') {
                                    otp.zeroize();
                                    self.notice = Some(Notice::plain(T::InvalidOtp));
                                } else if let Err(error) = self.controller.submit_otp(otp) {
                                    self.notice = Some(Notice::error(T::VerifyFailed, error));
                                } else {
                                    self.notice = None;
                                }
                            }
                        });
                    });
                });
            if response.should_close() {
                self.otp.zeroize();
                self.controller.disconnect();
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.password.zeroize();
        self.otp.zeroize();
        self.controller.shutdown();
    }
}

fn protocol_label(protocol: VpnProtocol) -> T {
    match protocol {
        VpnProtocol::Huawei => T::ProtocolHuawei,
        VpnProtocol::Cisco => T::ProtocolCisco,
        VpnProtocol::OpenVpn => T::ProtocolOpenVpn,
    }
}
fn transport_label(protocol: VpnProtocol, transport: TransportMode) -> T {
    match (protocol, transport) {
        (VpnProtocol::Huawei, TransportMode::Auto) => T::AutoOption,
        (VpnProtocol::Huawei, TransportMode::Tls) => T::TlsOption,
        (VpnProtocol::Huawei, TransportMode::Udp) => T::UdpOption,
        (VpnProtocol::Cisco, TransportMode::Auto) => T::CiscoAutoOption,
        (VpnProtocol::Cisco, TransportMode::Tls) => T::CiscoTlsOption,
        (VpnProtocol::Cisco, TransportMode::Udp) => T::CiscoUdpUnsupported,
        (VpnProtocol::OpenVpn, TransportMode::Auto) => T::OvpnAutoOption,
        (VpnProtocol::OpenVpn, TransportMode::Tls) => T::OvpnTcpOption,
        (VpnProtocol::OpenVpn, TransportMode::Udp) => T::OvpnUdpOption,
    }
}
fn transport_badge_label(protocol: VpnProtocol, transport: TransportMode) -> T {
    match (protocol, transport) {
        (VpnProtocol::Huawei, TransportMode::Auto) => T::AutoMode,
        (VpnProtocol::Huawei, TransportMode::Tls) => T::TlsMode,
        (VpnProtocol::Huawei, TransportMode::Udp) => T::UdpMode,
        _ => transport_label(protocol, transport),
    }
}
fn route_policy_label(mode: RouteMode) -> T {
    match mode {
        RouteMode::GatewayOnly => T::RouteGatewayOnly,
        RouteMode::Merge => T::RouteMerge,
        RouteMode::ManualOnly => T::RouteManual,
        RouteMode::FullTunnel => T::RouteFull,
    }
}

fn configure(ctx: &egui::Context, theme: Theme) {
    let mut fonts = egui::FontDefinitions::default();
    // Prefer a regular system UI face over egui's default Ubuntu Light.
    let latin_paths = [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ];
    if let Some(bytes) = latin_paths
        .into_iter()
        .find_map(|path| std::fs::read(path).ok())
    {
        fonts.font_data.insert(
            "ui-regular".into(),
            egui::FontData::from_owned(bytes).into(),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "ui-regular".into());
    }
    let cjk_paths = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "C:\\Windows\\Fonts\\msyh.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    ];
    if let Some(bytes) = cjk_paths
        .into_iter()
        .find_map(|path| std::fs::read(path).ok())
    {
        fonts.font_data.insert(
            "cjk-regular".into(),
            egui::FontData::from_owned(bytes).into(),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk-regular".into());
        }
    }
    ctx.set_fonts(fonts);
    for dark in [false, true] {
        let colors = theme_palette(dark);
        let mut style = egui::Style {
            visuals: if dark {
                egui::Visuals::dark()
            } else {
                egui::Visuals::light()
            },
            ..Default::default()
        };
        style.visuals.override_text_color = Some(colors.ink);
        style.visuals.weak_text_color = Some(colors.muted);
        style.visuals.selection.bg_fill = colors.pale;
        style.visuals.selection.stroke = Stroke::new(1.0, colors.blue);
        style.visuals.panel_fill = colors.background;
        style.visuals.window_fill = colors.surface;
        style.visuals.extreme_bg_color = colors.background;
        style.visuals.faint_bg_color = colors.pale;
        style.visuals.widgets.noninteractive.bg_fill = colors.surface;
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, colors.line);
        style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, colors.ink);
        style.visuals.widgets.inactive.bg_fill = colors.surface;
        style.visuals.widgets.inactive.weak_bg_fill = colors.surface;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, colors.line);
        style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, colors.ink);
        style.visuals.widgets.inactive.corner_radius = 6.into();
        style.visuals.widgets.hovered.bg_fill = colors.pale;
        style.visuals.widgets.hovered.weak_bg_fill = colors.pale;
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, colors.blue);
        style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, colors.ink);
        style.visuals.widgets.hovered.corner_radius = 6.into();
        style.visuals.widgets.active.bg_fill = colors.pale;
        style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, colors.ink);
        style.visuals.widgets.active.corner_radius = 6.into();
        style.spacing.item_spacing = Vec2::new(10.0, 8.0);
        style.spacing.button_padding = Vec2::new(12.0, 8.0);
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(13.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::proportional(12.0));
        ctx.set_style_of(
            if dark {
                egui::Theme::Dark
            } else {
                egui::Theme::Light
            },
            style,
        );
    }
    apply_theme(ctx, theme);
}

fn apply_theme(ctx: &egui::Context, theme: Theme) {
    ctx.set_theme(match theme {
        Theme::Light => egui::ThemePreference::Light,
        Theme::Dark => egui::ThemePreference::Dark,
    });
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(match theme {
        Theme::Light => egui::SystemTheme::Light,
        Theme::Dark => egui::SystemTheme::Dark,
    }));
}

fn action_row<R>(
    ui: &mut egui::Ui,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    // Reserve the button height before painting the title; a later, taller
    // widget cannot recenter a label that has already been laid out.
    let height = 32.0_f32
        .max(ui.spacing().interact_size.y)
        .max(ui.text_style_height(&egui::TextStyle::Button) + ui.spacing().button_padding.y * 2.0);
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), height),
        egui::Layout::left_to_right(Align::Center),
        contents,
    )
}

fn card(ui: &egui::Ui) -> egui::Frame {
    let colors = palette(ui);
    egui::Frame::new()
        .fill(colors.surface)
        .stroke(Stroke::new(1.0, colors.line))
        .corner_radius(13)
        .inner_margin(20.0)
}
fn field_label(ui: &mut egui::Ui, text: &str) {
    let colors = palette(ui);
    ui.label(RichText::new(text).size(12.0).color(colors.muted));
    ui.add_space(3.0);
}
fn metric(ui: &mut egui::Ui, title: &str, value: &str, detail: &str) {
    let colors = palette(ui);
    card(ui).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.label(RichText::new(title).size(12.0).color(colors.muted));
        ui.add_space(8.0);
        ui.label(RichText::new(value).size(23.0).strong().color(colors.ink));
        ui.add_space(8.0);
        ui.label(RichText::new(detail).size(12.0).color(colors.muted));
    });
}
fn badge(ui: &mut egui::Ui, text: &str) {
    let colors = palette(ui);
    egui::Frame::new()
        .fill(colors.pale)
        .corner_radius(5)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).color(colors.blue));
        });
}
fn logo(ui: &mut egui::Ui, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let c = rect.center();
    ui.painter().circle_filled(c, size * 0.48, color);
    let points = vec![
        c + Vec2::new(1.0, -10.0),
        c + Vec2::new(-7.0, 2.0),
        c + Vec2::new(-1.0, 2.0),
        c + Vec2::new(-1.0, 10.0),
        c + Vec2::new(7.0, -2.0),
        c + Vec2::new(1.0, -2.0),
    ];
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        Color32::WHITE,
        Stroke::NONE,
    ));
}
/// Keep the text edit's native frame and focus behavior, reserving space for an
/// independent, keyboard-accessible visibility button inside its right edge.
fn password_edit(
    ui: &mut egui::Ui,
    password: &mut String,
    visible: &mut bool,
    language: Language,
    mut margin: egui::Margin,
) -> egui::Response {
    margin.right += 32;
    let response = ui.add(
        egui::TextEdit::singleline(password)
            .password(!*visible)
            .hint_text(text(language, T::PasswordHint))
            .desired_width(f32::INFINITY)
            .margin(margin),
    );
    let button_rect = egui::Rect::from_min_max(
        egui::pos2(response.rect.right() - 34.0, response.rect.top() + 2.0),
        response.rect.right_bottom() - Vec2::splat(2.0),
    );
    let label = text(
        language,
        if *visible {
            T::HidePassword
        } else {
            T::ShowPassword
        },
    );
    let toggle = ui.interact(
        button_rect,
        response.id.with("password-visibility"),
        egui::Sense::click(),
    );
    toggle.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    let toggle = toggle.on_hover_text(label);
    if toggle.clicked() {
        *visible = !*visible;
        ui.ctx().request_repaint();
    }
    if ui.is_rect_visible(button_rect) {
        let visuals = ui.style().interact(&toggle);
        let painter = ui.painter();
        if toggle.hovered() || toggle.has_focus() || toggle.is_pointer_button_down_on() {
            painter.rect_filled(button_rect, 4, visuals.weak_bg_fill);
        }
        if toggle.has_focus() {
            painter.rect_stroke(button_rect, 4, visuals.fg_stroke, egui::StrokeKind::Inside);
        }
        let center = button_rect.center();
        let stroke = Stroke::new(1.5, visuals.fg_stroke.color);
        for direction in [-1.0, 1.0] {
            painter.add(egui::epaint::CubicBezierShape::from_points_stroke(
                [
                    center + Vec2::new(-9.0, 0.0),
                    center + Vec2::new(-4.5, 6.0 * direction),
                    center + Vec2::new(4.5, 6.0 * direction),
                    center + Vec2::new(9.0, 0.0),
                ],
                false,
                Color32::TRANSPARENT,
                stroke,
            ));
        }
        painter.circle_stroke(center, 2.5, stroke);
        if !*visible {
            painter.line_segment(
                [center + Vec2::new(-8.0, -6.0), center + Vec2::new(8.0, 6.0)],
                stroke,
            );
        }
    }
    response
}

fn bytes(value: u64) -> String {
    if value < 1024 {
        format!("{value} B")
    } else if value < 1024 * 1024 {
        format!("{:.1} KB", value as f64 / 1024.0)
    } else if value < 1024 * 1024 * 1024 {
        format!("{:.1} MB", value as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", value as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
fn duration(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestApp(App);
    impl TestApp {
        fn new() -> Self {
            let directory = std::env::temp_dir()
                .join(format!("sslray-ui-test-{:016x}", getrandom::u64().unwrap()));
            let profiles = ProfileLibrary::default();
            Self(App {
                controller: Controller::new(),
                profile: profiles.selected().profile.clone(),
                profiles,
                profile_dialog: None,
                profiles_writable: true,
                remember_password: false,
                confirm_password_storage: false,
                password_dialog: false,
                rejection_handled: false,
                password: String::new(),
                otp: String::new(),
                use_otp: false,
                show_password: false,
                route_text: String::new(),
                page: Page::Overview,
                notice: None,
                tray: None,
                hidden: false,
                quitting: false,
                preferences_path: Some(directory.join("ui-preferences.json")),
                config_dir: Some(directory),
                language: Language::ZhCn,
                theme: Theme::Light,
                challenge_prompted: false,
                challenge_focus: false,
                crypto_backend: String::new(),
                gm_available: false,
                adapter_display: AdapterDisplay::default(),
                adapter_query: None,
                authorization_retry: false,
                pending_password: None,
                pending_otp: None,
                certificate_query: None,
                certificate_review: None,
                certificate_approval: None,
            })
        }
    }
    impl Drop for TestApp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.config_dir.as_ref().unwrap());
        }
    }

    #[test]
    fn named_profile_selection_keeps_passwords_isolated_and_guards_drafts() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profile.username = "test-user".into();
        app.password = "local-test-only".into();
        app.remember_password = true;
        app.save().unwrap();
        let first = app.profiles.selected_id;
        app.perform_profile_action(ProfileAction::New);
        assert_ne!(first, app.profiles.selected_id);
        assert!(app.password.is_empty() && !app.remember_password);
        app.otp = "test-otp".into();
        app.use_otp = true;
        app.profile.host = "unsaved.example".into();
        app.request_profile_action(ProfileAction::Select(first));
        assert!(
            matches!(app.profile_dialog, Some(ProfileDialog::Unsaved(ProfileAction::Select(id))) if id == first)
        );
        assert_ne!(first, app.profiles.selected_id);
        // The modal's explicit discard path selects the saved draft, clears OTP,
        // and restores only the password belonging to the target profile.
        app.perform_profile_action(ProfileAction::Select(first));
        assert_eq!(app.password, "local-test-only");
        assert!(app.otp.is_empty() && !app.use_otp);
        assert!(!app.dirty());
        let loaded = ProfileLibrary::load(app.config_dir.as_ref().unwrap()).unwrap();
        assert_eq!(loaded.selected_id, first);
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(
            loaded
                .entries
                .iter()
                .filter(|entry| entry.saved_password.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn missing_session_password_prompts_without_elevation_or_disk_write() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profile.username = "test-user".into();
        app.connect();
        assert!(app.password_dialog);
        assert!(!app.controller.is_busy());
        assert!(!app.config_dir.as_ref().unwrap().exists());
    }

    fn simulated_certificate_report(trusted: bool) -> CertificateReport {
        CertificateReport {
            certificate_sha256: "ab".repeat(32),
            subject: "CN=synthetic-gateway".into(),
            issuer: "CN=synthetic-issuer".into(),
            not_before: "Jan 1 00:00:00 2026 GMT".into(),
            not_after: "Jan 1 00:00:00 2027 GMT".into(),
            verification_errors: if trusted {
                vec![]
            } else {
                vec!["self-signed certificate (code 18, depth 0)".into()]
            },
        }
    }

    #[test]
    fn untrusted_certificate_report_requires_review_without_starting_connection() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profile.username = "synthetic-user".into();
        app.otp = "123456".into();
        let target = CertificateTarget::new(app.profiles.selected_id, &app.profile);
        let report = simulated_certificate_report(false);
        let (sender, receiver) = std::sync::mpsc::channel();
        app.certificate_query = Some(CertificateQuery {
            target: target.clone(),
            receiver,
        });
        sender.send(Ok(report.clone())).unwrap();
        app.poll_certificate_check(&egui::Context::default());
        let review = app.certificate_review.as_ref().unwrap();
        assert_eq!(review.target, target);
        assert_eq!(review.report, report);
        assert!(!review.remember);
        assert!(app.certificate_query.is_none() && app.certificate_approval.is_none());
        assert!(!app.controller.is_busy() && !app.password_dialog);
        assert!(app.profile.certificate_sha256.is_empty());
        assert!(app.password.is_empty());
        assert_eq!(app.otp, "123456");
        assert!(app.pending_password.is_none() && app.pending_otp.is_none());
        assert!(!app.config_dir.as_ref().unwrap().exists());
    }

    #[test]
    fn cancelled_certificate_query_cannot_resume_from_a_late_trusted_report() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profile.username = "synthetic-user".into();
        let target = CertificateTarget::new(app.profiles.selected_id, &app.profile);
        let (old_sender, receiver) = std::sync::mpsc::channel();
        app.certificate_query = Some(CertificateQuery {
            target: target.clone(),
            receiver,
        });
        app.clear_certificate_check();
        let (_new_sender, receiver) = std::sync::mpsc::channel();
        app.certificate_query = Some(CertificateQuery { target, receiver });
        assert!(
            old_sender
                .send(Ok(simulated_certificate_report(true)))
                .is_err()
        );
        app.poll_certificate_check(&egui::Context::default());
        assert!(app.certificate_query.is_some());
        assert!(app.certificate_review.is_none() && app.certificate_approval.is_none());
        assert!(!app.controller.is_busy() && !app.password_dialog);
        assert!(app.profile.certificate_sha256.is_empty());
        assert!(app.pending_password.is_none() && app.pending_otp.is_none());
        assert!(!app.config_dir.as_ref().unwrap().exists());
    }

    #[test]
    fn changed_certificate_target_discards_queued_reports_reviews_and_approvals() {
        for field in ["profile", "host", "pin"] {
            let mut fixture = TestApp::new();
            let app = &mut fixture.0;
            // Even a regression that processes the simulated trusted report
            // cannot reach the network: the required password is absent.
            app.profile.username = "synthetic-user".into();
            let target = CertificateTarget::new(app.profiles.selected_id, &app.profile);
            let (sender, receiver) = std::sync::mpsc::channel();
            app.certificate_query = Some(CertificateQuery {
                target: target.clone(),
                receiver,
            });
            sender.send(Ok(simulated_certificate_report(true))).unwrap();
            match field {
                "profile" => {
                    app.profiles
                        .insert(Profile {
                            name: "Another profile".into(),
                            ..app.profile.clone()
                        })
                        .unwrap();
                }
                "host" => app.profile.host = "another.example".into(),
                "pin" => app.profile.certificate_sha256 = "cd".repeat(32),
                _ => unreachable!(),
            }
            let context = egui::Context::default();
            app.poll_certificate_check(&context);
            assert!(app.certificate_query.is_none() && app.certificate_review.is_none());
            assert!(app.certificate_approval.is_none());
            app.certificate_review = Some(CertificateReview {
                target: target.clone(),
                report: simulated_certificate_report(false),
                remember: false,
            });
            app.poll_certificate_check(&context);
            assert!(app.certificate_review.is_none());
            app.certificate_approval = Some(CertificateApproval {
                target,
                certificate_sha256: Some("ab".repeat(32)),
            });
            app.poll_certificate_check(&context);
            assert!(app.certificate_approval.is_none());
            assert!(!app.controller.is_busy() && !app.password_dialog);
            assert!(app.pending_password.is_none() && app.pending_otp.is_none());
            assert!(!app.config_dir.as_ref().unwrap().exists());
        }
    }

    #[test]
    fn certificate_approval_once_changes_only_the_connection_copy() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        let before = serde_json::to_value(&app.profile).unwrap();
        let review = CertificateReview {
            target: CertificateTarget::new(app.profiles.selected_id, &app.profile),
            report: simulated_certificate_report(false),
            remember: false,
        };
        app.approve_certificate(&review).unwrap();
        assert_eq!(serde_json::to_value(&app.profile).unwrap(), before);
        assert!(
            app.profiles
                .selected()
                .profile
                .certificate_sha256
                .is_empty()
        );
        let connection = app
            .certificate_approval
            .as_ref()
            .unwrap()
            .connection_profile(app.profiles.selected_id, &app.profile)
            .unwrap();
        assert_eq!(
            connection.certificate_sha256,
            review.report.certificate_sha256
        );
        let mut expected = before;
        expected["certificate_sha256"] =
            serde_json::Value::String(review.report.certificate_sha256.clone());
        assert_eq!(serde_json::to_value(&connection).unwrap(), expected);
        assert!(!app.config_dir.as_ref().unwrap().exists());
        assert!(!app.controller.is_busy());
        assert!(app.pending_password.is_none() && app.pending_otp.is_none());
    }

    #[test]
    fn remembered_certificate_persists_without_unapproved_password_or_otp_storage() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profile.username = "synthetic-user".into();
        app.password = "synthetic-main-password-not-saved".into();
        app.otp = "123456".into();
        app.use_otp = true;
        app.remember_password = false;
        let review = CertificateReview {
            target: CertificateTarget::new(app.profiles.selected_id, &app.profile),
            report: simulated_certificate_report(false),
            remember: true,
        };
        app.approve_certificate(&review).unwrap();
        let loaded = ProfileLibrary::load(app.config_dir.as_ref().unwrap()).unwrap();
        assert_eq!(loaded.selected_id, app.profiles.selected_id);
        assert_eq!(
            loaded.selected().profile.certificate_sha256,
            review.report.certificate_sha256
        );
        assert_eq!(
            app.profile.certificate_sha256,
            review.report.certificate_sha256
        );
        assert!(loaded.selected().saved_password.is_none());
        let stored =
            std::fs::read_to_string(app.config_dir.as_ref().unwrap().join("profiles.json"))
                .unwrap();
        assert!(!stored.contains("synthetic-main-password-not-saved"));
        assert!(!stored.contains("123456"));
        assert!(!stored.contains("\"saved_password\""));
        assert!(!stored.contains("\"saved_password_base64\""));
        assert!(!stored.contains("\"otp\""));
        assert_eq!(app.password, "synthetic-main-password-not-saved");
        assert_eq!(app.otp, "123456");
        assert!(app.certificate_approval.is_none());
        assert!(!app.controller.is_busy());
        assert!(app.pending_password.is_none() && app.pending_otp.is_none());
    }

    #[test]
    fn remembered_certificate_save_failure_restores_pin_without_connecting() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.profiles_writable = false;
        let before = serde_json::to_value(&app.profile).unwrap();
        let review = CertificateReview {
            target: CertificateTarget::new(app.profiles.selected_id, &app.profile),
            report: simulated_certificate_report(false),
            remember: true,
        };
        assert!(app.approve_certificate(&review).is_err());
        assert_eq!(serde_json::to_value(&app.profile).unwrap(), before);
        assert!(
            app.profiles
                .selected()
                .profile
                .certificate_sha256
                .is_empty()
        );
        assert!(app.certificate_approval.is_none());
        assert!(!app.config_dir.as_ref().unwrap().exists());
        assert!(!app.controller.is_busy());
        assert!(app.pending_password.is_none() && app.pending_otp.is_none());
    }

    #[test]
    fn optional_password_can_be_removed_and_theme_preferences_survive_restart() {
        let mut fixture = TestApp::new();
        let app = &mut fixture.0;
        app.password = "local-test-only".into();
        app.remember_password = true;
        app.save().unwrap();
        app.remember_password = false;
        app.save().unwrap();
        let loaded = ProfileLibrary::load(app.config_dir.as_ref().unwrap()).unwrap();
        assert!(loaded.selected().saved_password.is_none());
        app.theme = Theme::Dark;
        app.language = Language::En;
        app.save_preferences().unwrap();
        let preferences: UiPreferences =
            serde_json::from_slice(&std::fs::read(app.preferences_path.as_ref().unwrap()).unwrap())
                .unwrap();
        assert_eq!(preferences.theme, Theme::Dark);
        assert_eq!(preferences.language, Language::En);
        let legacy: UiPreferences = serde_json::from_str(r#"{"language":"en"}"#).unwrap();
        assert_eq!(legacy.theme, Theme::Light);
    }

    fn adapter_snapshot(state: ConnectionState, session_generation: u64) -> Snapshot {
        Snapshot {
            session_generation,
            state,
            interface: Some("utun40".into()),
            address: Some("192.0.2.2".into()),
            ..Snapshot::default()
        }
    }

    #[test]
    fn adapter_selection_follows_session_ownership_through_cleanup() {
        for state in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::AwaitingOtp,
        ] {
            let snapshot = adapter_snapshot(state, 1);
            assert!(AdapterTarget::from_snapshot(&snapshot, true, 1400).is_none());
        }
        for state in [
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
            ConnectionState::Failed,
        ] {
            let snapshot = adapter_snapshot(state, 1);
            let target = AdapterTarget::from_snapshot(&snapshot, true, 1400).unwrap();
            assert_eq!(target.name, "utun40");
            assert_eq!(target.address.as_deref(), Some("192.0.2.2"));
            assert!(AdapterTarget::from_snapshot(&snapshot, false, 1400).is_none());
        }
        let snapshot = Snapshot {
            state: ConnectionState::Failed,
            applied_routes: vec!["192.0.2.0/24".into()],
            ..Snapshot::default()
        };
        assert!(AdapterTarget::from_snapshot(&snapshot, false, 1400).is_none());
    }

    #[test]
    fn adapter_results_from_previous_same_name_sessions_or_refreshes_are_ignored() {
        let target = AdapterTarget::from_snapshot(
            &adapter_snapshot(ConnectionState::Connected, 1),
            true,
            1400,
        )
        .unwrap();
        let mut display = AdapterDisplay::default();
        display.select(Some(target.clone()));
        let old = display.refresh().unwrap();
        display.select(None);
        assert!(!display.accept(AdapterResponse {
            request: old.clone(),
            result: Ok(None)
        }));
        let next = AdapterTarget {
            session_generation: 2,
            ..target
        };
        display.select(Some(next.clone()));
        let current = display.refresh().unwrap();
        assert!(!display.accept(AdapterResponse {
            request: old,
            result: Err("old session failure".into())
        }));
        assert!(display.error.is_none() && display.metadata.is_none());
        let metadata = AdapterInfo {
            name: "utun40".into(),
            addresses: vec!["192.0.2.2/32".into()],
            is_up: true,
            virtual_interface: true,
            mtu: Some(1380),
        };
        assert!(display.accept(AdapterResponse {
            request: current.clone(),
            result: Ok(Some(metadata.clone()))
        }));
        assert_eq!(display.metadata, Some(metadata.clone()));
        let refreshed = display.refresh().unwrap();
        assert!(!display.accept(AdapterResponse {
            request: current,
            result: Ok(Some(metadata))
        }));
        assert!(display.accept(AdapterResponse {
            request: refreshed,
            result: Err("query failed".into())
        }));
        assert!(display.metadata.is_none());
        assert_eq!(display.target, Some(next));
        assert_eq!(display.error.as_deref(), Some("query failed"));
    }

    #[test]
    fn adapter_query_never_replaces_session_with_another_local_interface() {
        let mut display = AdapterDisplay::default();
        display.select(AdapterTarget::from_snapshot(
            &adapter_snapshot(ConnectionState::Connected, 1),
            true,
            1400,
        ));
        let request = display.refresh().unwrap();
        let other = AdapterInfo {
            name: "utun41".into(),
            addresses: vec![],
            is_up: true,
            virtual_interface: true,
            mtu: Some(1500),
        };
        assert!(display.accept(AdapterResponse {
            request,
            result: Ok(Some(other))
        }));
        assert!(display.metadata.is_none() && display.error.is_some());
        assert_eq!(display.target.as_ref().unwrap().name, "utun40");
        display.select(None);
        assert!(display.target.is_none() && display.error.is_none() && display.metadata.is_none());
        assert!(display.refresh().is_none());
    }
}
