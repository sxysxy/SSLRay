use crate::i18n::{Language, Text as T, text};
use anyhow::{Context, Result};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
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
    #[cfg(not(target_os = "linux"))]
    _icon: TrayIcon,
    #[cfg(not(target_os = "linux"))]
    labels: MenuLabels,
    #[cfg(target_os = "linux")]
    language: Sender<Language>,
}

struct MenuLabels {
    show: MenuItem,
    hide: MenuItem,
    disconnect: MenuItem,
    quit: MenuItem,
}
impl MenuLabels {
    fn set_language(&self, language: Language) {
        self.show.set_text(text(language, T::TrayShow));
        self.hide.set_text(text(language, T::TrayHide));
        self.disconnect.set_text(text(language, T::Disconnect));
        self.quit.set_text(text(language, T::TrayQuit));
    }
}

fn build(
    context: egui::Context,
    tx: Sender<Action>,
    language: Language,
) -> Result<(TrayIcon, MenuLabels)> {
    let menu = Menu::new();
    let show = MenuItem::new(text(language, T::TrayShow), true, None);
    let hide = MenuItem::new(text(language, T::TrayHide), true, None);
    let disconnect = MenuItem::new(text(language, T::Disconnect), true, None);
    let quit = MenuItem::new(text(language, T::TrayQuit), true, None);
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
    let rgba = icon_rgba(32)?;
    let icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(Icon::from_rgba(rgba, 32, 32)?)
        .with_tooltip("SSLRay · SSL VPN")
        .with_menu_on_left_click(true)
        .build()
        .context(text(language, T::TrayCreateFailed))?;
    Ok((
        icon,
        MenuLabels {
            show,
            hide,
            disconnect,
            quit,
        },
    ))
}

impl Tray {
    pub fn new(context: egui::Context, language: Language) -> Result<Self> {
        let (tx, actions) = mpsc::channel();
        #[cfg(not(target_os = "linux"))]
        {
            let (icon, labels) = build(context, tx, language)?;
            Ok(Self {
                actions,
                _icon: icon,
                labels,
            })
        }
        #[cfg(target_os = "linux")]
        {
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let (language_tx, language_rx) = mpsc::channel();
            std::thread::spawn(move || {
                if let Err(error) = gtk::init() {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
                match build(context, tx, language) {
                    Ok((icon, labels)) => {
                        let _ = ready_tx.send(Ok(()));
                        gtk::glib::timeout_add_local(
                            std::time::Duration::from_millis(150),
                            move || {
                                for language in language_rx.try_iter() {
                                    labels.set_language(language);
                                }
                                gtk::glib::ControlFlow::Continue
                            },
                        );
                        gtk::main();
                        drop(icon);
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
                language: language_tx,
            })
        }
    }

    pub fn set_language(&mut self, language: Language) {
        #[cfg(not(target_os = "linux"))]
        self.labels.set_language(language);
        #[cfg(target_os = "linux")]
        let _ = self.language.send(language);
    }
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
