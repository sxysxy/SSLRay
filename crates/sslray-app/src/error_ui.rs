//! Presentation only: summaries never contain raw backend text. Callers should
//! use distinct `ui.push_id` scopes for separate notices or log entries.
use crate::diagnostics::{self, DiagnosticKind};
use crate::i18n::{self, Language, Text as T, text};
use eframe::egui::{self, Align, Color32, FontId, Vec2};

/// Render a bounded notice and return whether its close button was clicked.
pub fn notice(ui: &mut egui::Ui, language: Language, title: &str, detail: Option<&str>) -> bool {
    let diagnostic = detail.map(|raw| diagnostics::describe(language, raw));
    let localized = detail.and_then(|raw| i18n::known_diagnostic(language, raw));
    let summary = diagnostic
        .as_ref()
        .filter(|diagnostic| diagnostic.kind != DiagnosticKind::Unknown)
        .map_or_else(
            || localized.as_deref().unwrap_or(title),
            |diagnostic| diagnostic.summary,
        );
    let width = ui.available_width().max(1.0);
    let frame = egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(8)
        .inner_margin(12);
    let inner_width = (width - frame.total_margin().sum().x).max(1.0);
    let mut dismiss = false;
    frame.show(ui, |ui| {
        ui.set_width(inner_width);
        ui.set_max_width(inner_width);
        ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
            let top_left = ui.next_widget_position();
            let close_size = 24.0_f32.min(inner_width);
            let close_rect = egui::Rect::from_min_size(
                top_left + Vec2::new(inner_width - close_size, 0.0),
                Vec2::splat(close_size),
            );
            // Reserve a separate column for the close button. Its position is
            // independent of a multiline heading and the expanded detail body.
            let summary_width = (inner_width - close_size - 8.0).max(1.0);
            ui.allocate_ui_with_layout(
                Vec2::new(summary_width, close_size),
                egui::Layout::top_down(Align::Min),
                |ui| {
                    ui.set_min_height(close_size);
                    ui.set_max_width(summary_width);
                    let color = ui.visuals().strong_text_color();
                    bounded_label(ui, summary, 14.0, color, false);
                },
            );
            dismiss = ui
                .place(
                    close_rect,
                    egui::Button::new("×")
                        .frame(false)
                        .min_size(Vec2::splat(close_size)),
                )
                .clicked();
            if let Some(raw) = diagnostic
                .as_ref()
                .and_then(|diagnostic| diagnostic.technical_detail)
            {
                ui.add_space(6.0);
                technical_detail(ui, language, raw);
            }
        });
    });
    dismiss
}

/// Render the fixed diagnostic summary, followed by opt-in technical details.
pub fn error(ui: &mut egui::Ui, language: Language, raw: &str) {
    let diagnostic = diagnostics::describe(language, raw);
    let localized = i18n::known_diagnostic(language, raw);
    let summary = if diagnostic.kind == DiagnosticKind::Unknown {
        localized.as_deref().unwrap_or(diagnostic.summary)
    } else {
        diagnostic.summary
    };
    let width = ui.available_width().max(1.0);
    ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
        ui.set_max_width(width);
        let color = ui.visuals().warn_fg_color;
        bounded_label(ui, summary, 14.0, color, false);
        if let Some(raw) = diagnostic.technical_detail {
            ui.add_space(6.0);
            technical_detail(ui, language, raw);
        }
    });
}

/// Raw text is collapsed by default and is never parsed as commands or markup.
pub fn technical_detail(ui: &mut egui::Ui, language: Language, raw: &str) {
    if raw.trim().is_empty() {
        return;
    }
    let width = ui.available_width().max(1.0);
    ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
        ui.set_max_width(width);
        egui::CollapsingHeader::new(text(language, T::TechnicalDetails))
            .id_salt("error-technical-details")
            .default_open(false)
            .show(ui, |ui| {
                let width = ui.available_width().max(1.0);
                ui.set_max_width(width);
                if ui
                    .add(egui::Button::new(text(language, T::CopyErrorDetails)).wrap())
                    .clicked()
                {
                    ui.ctx().copy_text(raw.to_owned());
                }
                ui.add_space(6.0);
                let frame = egui::Frame::new()
                    .fill(ui.visuals().extreme_bg_color)
                    .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                    .corner_radius(5)
                    .inner_margin(8);
                let inner_width = (width - frame.total_margin().sum().x).max(1.0);
                frame.show(ui, |ui| {
                    ui.set_width(inner_width);
                    ui.set_max_width(inner_width);
                    egui::ScrollArea::vertical()
                        .id_salt("error-technical-detail-scroll")
                        .max_height(160.0)
                        .min_scrolled_height(0.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.set_max_width(ui.available_width());
                            let color = ui.visuals().text_color();
                            bounded_label(ui, raw, 12.0, color, true);
                        });
                });
            });
    });
}

fn bounded_label(
    ui: &mut egui::Ui,
    content: &str,
    font_size: f32,
    color: Color32,
    selectable: bool,
) -> egui::Response {
    let width = ui.available_width().max(1.0);
    ui.set_max_width(width);
    let mut layout = egui::text::LayoutJob::simple(
        content.to_owned(),
        FontId::proportional(font_size),
        color,
        width,
    );
    layout.wrap.break_anywhere = true;
    ui.add(
        egui::Label::new(layout)
            .wrap()
            .halign(Align::Min)
            .selectable(selectable),
    )
}
