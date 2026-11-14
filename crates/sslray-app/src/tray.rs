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
    let rgba = icon_rgba(32);
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

pub fn icon_rgba(size: u32) -> Vec<u8> {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let nx = (x as f32 + 0.5) / size as f32;
            let ny = (y as f32 + 0.5) / size as f32;
            let dx = nx - 0.5;
            let dy = ny - 0.5;
            let inside = dx * dx + dy * dy <= 0.225;
            let bolt = ((0.45..0.64).contains(&nx) && (0.20..0.49).contains(&ny))
                || ((0.32..0.64).contains(&nx) && (0.43..0.57).contains(&ny))
                || ((0.32..0.51).contains(&nx) && (0.51..0.80).contains(&ny));
            let color = if inside && bolt {
                [255, 255, 255, 255]
            } else if inside {
                [44, 102, 239, 255]
            } else {
                [0, 0, 0, 0]
            };
            rgba.extend_from_slice(&color);
        }
    }
    rgba
}
