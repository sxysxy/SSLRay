use crate::i18n::{Language, Text as T, text};
use crate::runtime::ConnectionState;
use anyhow::{Context, Result};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
#[cfg(any(target_os = "linux", test))]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Show,
    Hide,
    Disconnect,
    Quit,
}

pub struct Tray {
    pub actions: Receiver<Action>,
    updates: PresentationUpdates,
    #[cfg(not(target_os = "linux"))]
    native: NativeTray,
    #[cfg(target_os = "linux")]
    pending: Arc<LatestPresentation>,
    #[cfg(target_os = "linux")]
    outcomes: Receiver<UpdateOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Disconnected,
    Connecting,
    AwaitingOtp,
    Connected,
    Disconnecting,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusColor {
    Blue,
    Green,
    Amber,
    Red,
}
impl StatusColor {
    fn rgb(self) -> [u8; 3] {
        match self {
            Self::Blue => [35, 94, 221],
            Self::Green => [32, 158, 98],
            Self::Amber => [214, 148, 24],
            Self::Red => [210, 69, 76],
        }
    }
}

/// State and language always travel together, including across the GTK thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Presentation {
    status: Status,
    language: Language,
}

/// Keep successful frames cheap and report a persistent native error once.
/// A transient failure can recover, with at most one retry every five seconds.
struct PresentationUpdates {
    requested: Presentation,
    retry_at: Option<Instant>,
    reported_error: Option<String>,
}
impl PresentationUpdates {
    fn new(requested: Presentation) -> Self {
        Self {
            requested,
            retry_at: None,
            reported_error: None,
        }
    }

    fn request(&mut self, next: Presentation, now: Instant) -> bool {
        if self.requested != next {
            self.requested = next;
            self.retry_at = None;
            self.reported_error = None;
            return true;
        }
        if self.retry_at.is_some_and(|deadline| now >= deadline) {
            self.retry_at = None;
            return true;
        }
        false
    }

    fn failed(&mut self, error: String, now: Instant) -> Option<String> {
        self.retry_at = Some(now + Duration::from_secs(5));
        if self.reported_error.as_ref() == Some(&error) {
            None
        } else {
            self.reported_error = Some(error.clone());
            Some(error)
        }
    }

    fn applied(&mut self) {
        self.retry_at = None;
        self.reported_error = None;
    }
}
impl Presentation {
    fn new(state: ConnectionState, language: Language) -> Self {
        let status = match state {
            ConnectionState::Disconnected => Status::Disconnected,
            ConnectionState::Connecting => Status::Connecting,
            ConnectionState::AwaitingOtp => Status::AwaitingOtp,
            ConnectionState::Connected => Status::Connected,
            ConnectionState::Disconnecting => Status::Disconnecting,
            ConnectionState::Failed => Status::Failed,
        };
        Self { status, language }
    }

    fn color(self) -> StatusColor {
        match self.status {
            Status::Disconnected => StatusColor::Blue,
            Status::Connected => StatusColor::Green,
            Status::Connecting | Status::AwaitingOtp | Status::Disconnecting => StatusColor::Amber,
            Status::Failed => StatusColor::Red,
        }
    }

    fn can_disconnect(self) -> bool {
        self.status == Status::Connected
    }

    fn tooltip(self) -> String {
        let label = match self.status {
            Status::Disconnected => T::TrayDisconnected,
            Status::Connecting => T::Connecting,
            Status::AwaitingOtp => T::AwaitingOtp,
            Status::Connected => T::Connected,
            Status::Disconnecting => T::Disconnecting,
            Status::Failed => T::Failed,
        };
        format!("SSLRay · {}", text(self.language, label))
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
struct LatestPresentation(Mutex<Option<Presentation>>);
#[cfg(any(target_os = "linux", test))]
impl LatestPresentation {
    fn publish(&self, value: Presentation) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Tray status mailbox is unavailable"))? = Some(value);
        Ok(())
    }

    fn take(&self) -> Result<Option<Presentation>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("Tray status mailbox is unavailable"))?
            .take())
    }
}

#[cfg(target_os = "linux")]
struct UpdateOutcome {
    presentation: Presentation,
    error: Option<String>,
}

struct MenuLabels {
    show: MenuItem,
    hide: MenuItem,
    disconnect: MenuItem,
    quit: MenuItem,
    #[cfg(target_os = "linux")]
    status: MenuItem,
}
impl MenuLabels {
    fn set_language(&self, language: Language) {
        self.show.set_text(text(language, T::TrayShow));
        self.hide.set_text(text(language, T::TrayHide));
        self.disconnect.set_text(text(language, T::Disconnect));
        self.quit.set_text(text(language, T::TrayQuit));
    }
}

struct StatusIcons {
    blue: Icon,
    green: Icon,
    amber: Icon,
    red: Icon,
}
impl StatusIcons {
    fn new() -> Result<Self> {
        let make =
            |color| Icon::from_rgba(tray_icon_rgba(color)?, 32, 32).map_err(anyhow::Error::from);
        Ok(Self {
            blue: make(StatusColor::Blue)?,
            green: make(StatusColor::Green)?,
            amber: make(StatusColor::Amber)?,
            red: make(StatusColor::Red)?,
        })
    }

    fn get(&self, color: StatusColor) -> Icon {
        match color {
            StatusColor::Blue => &self.blue,
            StatusColor::Green => &self.green,
            StatusColor::Amber => &self.amber,
            StatusColor::Red => &self.red,
        }
        .clone()
    }
}

struct NativeTray {
    icon: TrayIcon,
    labels: MenuLabels,
    icons: StatusIcons,
    applied: Option<Presentation>,
}
impl NativeTray {
    fn apply(&mut self, next: Presentation) -> Result<()> {
        if self.applied == Some(next) {
            return Ok(());
        }
        // Invalidate before any fallible change: a partially updated native
        // item must be fully restored even if the desired state changes back.
        let previous = self.applied.take();
        // A failed icon update must never leave a stale Disconnect action enabled.
        if !next.can_disconnect() {
            self.labels.disconnect.set_enabled(false);
        }
        if previous.is_none_or(|value| value.language != next.language) {
            self.labels.set_language(next.language);
        }
        #[cfg(target_os = "linux")]
        self.labels.status.set_text(next.tooltip());
        if previous.is_none_or(|value| value.color() != next.color()) {
            let icon = self.icons.get(next.color());
            #[cfg(target_os = "macos")]
            self.icon.set_icon_with_as_template(Some(icon), false)?;
            #[cfg(not(target_os = "macos"))]
            self.icon.set_icon(Some(icon))?;
        }
        self.icon.set_tooltip(Some(next.tooltip()))?;
        self.labels.disconnect.set_enabled(next.can_disconnect());
        self.applied = Some(next);
        Ok(())
    }
}

fn build(context: egui::Context, tx: Sender<Action>, language: Language) -> Result<NativeTray> {
    let presentation = Presentation::new(ConnectionState::Disconnected, language);
    let menu = Menu::new();
    let show = MenuItem::new(text(language, T::TrayShow), true, None);
    let hide = MenuItem::new(text(language, T::TrayHide), true, None);
    let disconnect = MenuItem::new(text(language, T::Disconnect), false, None);
    let quit = MenuItem::new(text(language, T::TrayQuit), true, None);
    #[cfg(target_os = "linux")]
    let status = MenuItem::new(presentation.tooltip(), false, None);
    #[cfg(target_os = "linux")]
    menu.append_items(&[&status, &PredefinedMenuItem::separator()])?;
    menu.append_items(&[
        &show,
        &hide,
        &PredefinedMenuItem::separator(),
        &disconnect,
        &PredefinedMenuItem::separator(),
        &quit,
    ])?;
    let show_id = show.id().clone();
    let hide_id = hide.id().clone();
    let disconnect_id = disconnect.id().clone();
    let quit_id = quit.id().clone();
    let menu_context = context.clone();
    let menu_tx = tx.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let action = if event.id == show_id {
            Some(Action::Show)
        } else if event.id == hide_id {
            Some(Action::Hide)
        } else if event.id == disconnect_id {
            Some(Action::Disconnect)
        } else if event.id == quit_id {
            Some(Action::Quit)
        } else {
            None
        };
        if let Some(action) = action {
            let _ = menu_tx.send(action);
            menu_context.request_repaint();
        }
    }));
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if matches!(event, TrayIconEvent::DoubleClick { .. }) {
            let _ = tx.send(Action::Show);
            context.request_repaint();
        }
    }));
    let icons = StatusIcons::new()?;
    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icons.get(presentation.color()))
        .with_icon_as_template(false)
        .with_tooltip(presentation.tooltip())
        .with_menu_on_left_click(true)
        .build()
        .context(text(language, T::TrayCreateFailed))?;
    Ok(NativeTray {
        icon,
        labels: MenuLabels {
            show,
            hide,
            disconnect,
            quit,
            #[cfg(target_os = "linux")]
            status,
        },
        icons,
        applied: Some(presentation),
    })
}

impl Tray {
    pub fn new(context: egui::Context, language: Language) -> Result<Self> {
        let (tx, actions) = mpsc::channel();
        let presentation = Presentation::new(ConnectionState::Disconnected, language);
        #[cfg(not(target_os = "linux"))]
        {
            let native = build(context, tx, language)?;
            Ok(Self {
                actions,
                updates: PresentationUpdates::new(presentation),
                native,
            })
        }
        #[cfg(target_os = "linux")]
        {
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let pending = Arc::new(LatestPresentation::default());
            let worker_pending = Arc::clone(&pending);
            let (outcomes_tx, outcomes) = mpsc::channel();
            std::thread::spawn(move || {
                if let Err(error) = gtk::init() {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
                match build(context.clone(), tx, language) {
                    Ok(mut native) => {
                        let _ = ready_tx.send(Ok(()));
                        let mut last = presentation;
                        gtk::glib::timeout_add_local(
                            std::time::Duration::from_millis(150),
                            move || {
                                match worker_pending.take() {
                                    Ok(Some(next)) => {
                                        last = next;
                                        let error = native
                                            .apply(next)
                                            .err()
                                            .map(|error| format!("{error:#}"));
                                        let _ = outcomes_tx.send(UpdateOutcome {
                                            presentation: next,
                                            error,
                                        });
                                        context.request_repaint();
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        let _ = outcomes_tx.send(UpdateOutcome {
                                            presentation: last,
                                            error: Some(error.to_string()),
                                        });
                                        context.request_repaint();
                                        gtk::main_quit();
                                        return gtk::glib::ControlFlow::Break;
                                    }
                                }
                                gtk::glib::ControlFlow::Continue
                            },
                        );
                        gtk::main();
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                    }
                }
            });
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))?
                .map_err(|error| anyhow::anyhow!(error))?;
            Ok(Self {
                actions,
                updates: PresentationUpdates::new(presentation),
                pending,
                outcomes,
            })
        }
    }

    /// Call after every controller poll, including while the window is hidden.
    /// Linux applies one latest complete snapshot on its GTK thread; any async
    /// failure wakes the UI and is returned here once, with throttled retries.
    pub fn set_status(&mut self, state: ConnectionState, language: Language) -> Result<()> {
        let next = Presentation::new(state, language);
        let now = Instant::now();
        let requested = self.updates.request(next, now);
        #[cfg(not(target_os = "linux"))]
        if requested {
            match self.native.apply(next) {
                Ok(()) => self.updates.applied(),
                Err(error) => {
                    if let Some(error) = self.updates.failed(format!("{error:#}"), now) {
                        return Err(anyhow::anyhow!(error))
                            .context(text(language, T::TrayUpdateFailed));
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            // Drain acknowledgements even if the requested state is unchanged.
            // Only the latest matching outcome can change this presentation.
            let mut latest = None;
            let mut stopped = false;
            loop {
                match self.outcomes.try_recv() {
                    Ok(outcome) if outcome.presentation == next => latest = Some(outcome),
                    Ok(_) => {}
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        stopped = true;
                        break;
                    }
                }
            }
            let error = if stopped {
                Some("The system tray update thread stopped".to_owned())
            } else if let Some(outcome) = latest {
                if outcome.error.is_none() {
                    self.updates.applied();
                }
                outcome.error
            } else {
                None
            };
            let reported = error.and_then(|error| self.updates.failed(error, now));
            if requested
                && !stopped
                && let Err(error) = self.pending.publish(next)
                && let Some(error) = self.updates.failed(error.to_string(), now)
            {
                return Err(anyhow::anyhow!(error)).context(text(language, T::TrayUpdateFailed));
            }
            if let Some(error) = reported {
                return Err(anyhow::anyhow!(error)).context(text(language, T::TrayUpdateFailed));
            }
        }
        Ok(())
    }
}

/// Recolor only the existing SVG circle. Recover the white bolt's continuous
/// coverage from the original blue/white blend; no hard pixel thresholds or
/// new drawing geometry are introduced, and every alpha byte is retained.
fn tray_icon_rgba(color: StatusColor) -> Result<Vec<u8>> {
    let mut rgba = icon_rgba(32)?;
    if color == StatusColor::Blue {
        // Disconnected keeps the original branded PNG byte for byte.
        return Ok(rgba);
    }
    let blue = [35.0_f32, 94.0, 221.0];
    let white_delta = blue.map(|value| 255.0 - value);
    let denominator: f32 = white_delta.iter().map(|value| value * value).sum();
    let target = color.rgb();
    for pixel in rgba.chunks_exact_mut(4) {
        if pixel[3] == 0 {
            continue;
        }
        let coverage = (pixel[..3]
            .iter()
            .zip(blue)
            .zip(white_delta)
            .map(|((channel, base), delta)| (f32::from(*channel) - base) * delta)
            .sum::<f32>()
            / denominator)
            .clamp(0.0, 1.0);
        for (channel, target) in pixel[..3].iter_mut().zip(target) {
            *channel = (f32::from(target) * (1.0 - coverage) + 255.0 * coverage).round() as u8;
        }
    }
    Ok(rgba)
}

/// Load antialiased artwork rendered from assets/sslray.svg. The tray (32 px)
/// and window (64 px) use exact-size PNGs; other sizes retain this helper's API.
pub fn icon_rgba(size: u32) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    anyhow::ensure!(size <= 1024, "Icon size must not exceed the 1024px source");
    let png: &[u8] = match size {
        16 => include_bytes!("../../../assets/icons/sslray-16.png"),
        20 => include_bytes!("../../../assets/icons/sslray-20.png"),
        24 => include_bytes!("../../../assets/icons/sslray-24.png"),
        32 => include_bytes!("../../../assets/icons/sslray-32.png"),
        40 => include_bytes!("../../../assets/icons/sslray-40.png"),
        48 => include_bytes!("../../../assets/icons/sslray-48.png"),
        64 => include_bytes!("../../../assets/icons/sslray-64.png"),
        128 => include_bytes!("../../../assets/icons/sslray-128.png"),
        256 => include_bytes!("../../../assets/icons/sslray-256.png"),
        512 => include_bytes!("../../../assets/icons/sslray-512.png"),
        _ => include_bytes!("../../../assets/icons/sslray-1024.png"),
    };
    let icon = eframe::icon_data::from_png_bytes(png)
        .context("Loading the bundled SSLRay application icon")?;
    if icon.width == size {
        return Ok(icon.rgba);
    }

    // Bilinear sampling in premultiplied alpha avoids a dark fringe where the
    // transparent background meets the blue circle at nonstandard sizes.
    let mut rgba = vec![0; (size * size * 4) as usize];
    let scale = icon.width as f32 / size as f32;
    for y in 0..size {
        for x in 0..size {
            let sx = ((x as f32 + 0.5) * scale - 0.5).clamp(0.0, (icon.width - 1) as f32);
            let sy = ((y as f32 + 0.5) * scale - 0.5).clamp(0.0, (icon.height - 1) as f32);
            let x0 = sx.floor() as u32;
            let y0 = sy.floor() as u32;
            let dx = sx - x0 as f32;
            let dy = sy - y0 as f32;
            let mut channels = [0.0; 4];
            for (px, py, weight) in [
                (x0, y0, (1.0 - dx) * (1.0 - dy)),
                ((x0 + 1).min(icon.width - 1), y0, dx * (1.0 - dy)),
                (x0, (y0 + 1).min(icon.height - 1), (1.0 - dx) * dy),
                (
                    (x0 + 1).min(icon.width - 1),
                    (y0 + 1).min(icon.height - 1),
                    dx * dy,
                ),
            ] {
                let offset = ((py * icon.width + px) * 4) as usize;
                let alpha = f32::from(icon.rgba[offset + 3]) * weight;
                channels[3] += alpha;
                for (channel, value) in channels[..3].iter_mut().enumerate() {
                    *value += f32::from(icon.rgba[offset + channel]) * alpha;
                }
            }
            let offset = ((y * size + x) * 4) as usize;
            if channels[3] > 0.0 {
                for (output, value) in rgba[offset..offset + 3].iter_mut().zip(&channels[..3]) {
                    *output = (value / channels[3]).round() as u8;
                }
            }
            rgba[offset + 3] = channels[3].round() as u8;
        }
    }
    Ok(rgba)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_follows_connection_failure_reconnect_and_disconnect() {
        for (state, color, disconnect) in [
            (ConnectionState::Disconnected, StatusColor::Blue, false),
            (ConnectionState::Connecting, StatusColor::Amber, false),
            (ConnectionState::AwaitingOtp, StatusColor::Amber, false),
            (ConnectionState::Connected, StatusColor::Green, true),
            (ConnectionState::Failed, StatusColor::Red, false),
            (ConnectionState::Disconnected, StatusColor::Blue, false),
            (ConnectionState::Connecting, StatusColor::Amber, false),
            (ConnectionState::Connected, StatusColor::Green, true),
            (ConnectionState::Disconnecting, StatusColor::Amber, false),
            (ConnectionState::Disconnected, StatusColor::Blue, false),
        ] {
            let value = Presentation::new(state, Language::En);
            assert_eq!(value.color(), color);
            assert_eq!(value.can_disconnect(), disconnect);
        }
    }

    #[test]
    fn language_updates_tooltip_without_reenabling_disconnected_actions() {
        for state in [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::AwaitingOtp,
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
            ConnectionState::Failed,
        ] {
            let zh = Presentation::new(state.clone(), Language::ZhCn);
            let en = Presentation::new(state, Language::En);
            assert_ne!(zh.tooltip(), en.tooltip());
            assert!(en.tooltip().starts_with("SSLRay · "));
            assert_eq!(zh.color(), en.color());
            assert_eq!(zh.can_disconnect(), en.can_disconnect());
        }
        assert_eq!(
            Presentation::new(ConnectionState::Disconnected, Language::En).tooltip(),
            "SSLRay · Disconnected"
        );
        assert_eq!(
            Presentation::new(ConnectionState::Disconnected, Language::ZhCn).tooltip(),
            "SSLRay · 未连接"
        );
    }

    #[test]
    fn status_icons_retain_white_bolt_transparency_and_antialiased_edge() {
        let original = icon_rgba(32).unwrap();
        assert_eq!(tray_icon_rgba(StatusColor::Blue).unwrap(), original);
        assert!(
            original
                .chunks_exact(4)
                .any(|pixel| pixel[3] > 0 && pixel[3] < 255)
        );
        assert!(
            original
                .chunks_exact(4)
                .any(|pixel| pixel == [255, 255, 255, 255])
        );
        let mut variants = Vec::new();
        for color in [
            StatusColor::Blue,
            StatusColor::Green,
            StatusColor::Amber,
            StatusColor::Red,
        ] {
            let rgba = tray_icon_rgba(color).unwrap();
            assert_eq!(rgba.len(), 32 * 32 * 4);
            for (source, target) in original.chunks_exact(4).zip(rgba.chunks_exact(4)) {
                assert_eq!(source[3], target[3]);
                if source[..3] == [255, 255, 255] || source[3] == 0 {
                    assert_eq!(source, target);
                }
                if source[..3] == [35, 94, 221] && source[3] != 0 {
                    assert_eq!(target[..3], color.rgb());
                }
            }
            assert!(variants.iter().all(|previous| previous != &rgba));
            variants.push(rgba);
        }
        let window = eframe::icon_data::from_png_bytes(include_bytes!(
            "../../../assets/icons/sslray-64.png"
        ))
        .unwrap();
        assert_eq!(icon_rgba(64).unwrap(), window.rgba);
    }

    #[test]
    fn unchanged_status_is_cached_and_failures_are_throttled_reported_once() {
        let disconnected = Presentation::new(ConnectionState::Disconnected, Language::En);
        let connected = Presentation::new(ConnectionState::Connected, Language::En);
        let mut updates = PresentationUpdates::new(disconnected);
        let now = Instant::now();
        assert!(!updates.request(disconnected, now));
        assert!(updates.request(connected, now));
        assert_eq!(
            updates.failed("native icon write failed".into(), now),
            Some("native icon write failed".into())
        );
        for millis in [200, 800, 2000, 4999] {
            assert!(!updates.request(connected, now + Duration::from_millis(millis)));
        }
        let retry = now + Duration::from_secs(5);
        assert!(updates.request(connected, retry));
        assert_eq!(
            updates.failed("native icon write failed".into(), retry),
            None
        );
        assert!(!updates.request(connected, retry + Duration::from_millis(200)));
        assert!(updates.request(connected, now + Duration::from_secs(10)));
        updates.applied();
        assert!(!updates.request(connected, now + Duration::from_secs(20)));
        assert!(updates.request(disconnected, now + Duration::from_secs(21)));
        assert_eq!(updates.requested.color(), StatusColor::Blue);
        assert!(!updates.requested.can_disconnect());
    }

    #[test]
    fn gtk_mailbox_delivers_only_latest_complete_language_and_state() {
        let latest = LatestPresentation::default();
        latest
            .publish(Presentation::new(ConnectionState::Connected, Language::En))
            .unwrap();
        latest
            .publish(Presentation::new(ConnectionState::Failed, Language::ZhCn))
            .unwrap();
        let disconnected = Presentation::new(ConnectionState::Disconnected, Language::ZhCn);
        latest.publish(disconnected).unwrap();
        assert_eq!(latest.take().unwrap(), Some(disconnected));
        assert_eq!(latest.take().unwrap(), None);
    }

    #[test]
    fn gtk_mailbox_lock_failure_is_reported_without_a_native_tray() {
        let latest = Arc::new(LatestPresentation::default());
        let poisoned = Arc::clone(&latest);
        assert!(
            std::thread::spawn(move || {
                let _guard = poisoned.0.lock().unwrap();
                panic!("synthetic mailbox worker failure");
            })
            .join()
            .is_err()
        );
        assert!(
            latest
                .publish(Presentation::new(ConnectionState::Connected, Language::En))
                .is_err()
        );
        assert!(latest.take().is_err());
    }
}
