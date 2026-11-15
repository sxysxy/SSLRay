//! Certificate review UI only. Network actions and trust state belong to the caller.
use crate::error_ui;
use crate::i18n::{Language, Text as T, text};
use eframe::egui::{self, Align, FontId, RichText, Vec2};
use sslray_core::crypto::CertificateReport;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateChoice {
    Cancel,
    Continue,
}

/// Return true when the user cancels, presses Escape, or closes the modal.
pub fn checking(
    ctx: &egui::Context,
    language: Language,
    profile_name: &str,
    endpoint: &str,
) -> bool {
    let size = dialog_size(ctx);
    let mut cancel = false;
    let response = egui::Modal::new(egui::Id::new("certificate-checking")).show(ctx, |ui| {
        let (bounds, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let mut header = region(ui, "checking-header", bounds);
        title(&mut header, text(language, T::CertificateCheckingTitle));
        let footer_height = measure_footer(ui, "checking-footer-measure", bounds, |ui| {
            checking_footer(ui, language);
        });
        let footer_rect = footer_rect(bounds, footer_height);
        cancel = checking_footer(&mut region(ui, "checking-footer", footer_rect), language);
        let body_rect = body_rect(bounds, header.min_rect().bottom(), footer_rect.top());
        let mut body = region(ui, "checking-body", body_rect);
        egui::ScrollArea::vertical()
            .id_salt("certificate-checking-scroll")
            .max_height(body_rect.height())
            .min_scrolled_height(0.0)
            .auto_shrink([false, false])
            .show(&mut body, |ui| {
                ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
                    ui.set_max_width(ui.available_width());
                    ui.spinner();
                    wrapped(ui, text(language, T::CertificateCheckingHelp));
                    ui.add_space(14.0);
                    field(ui, language, T::CertificateProfile, profile_name, false);
                    field(ui, language, T::CertificateEndpoint, endpoint, false);
                });
            });
    });
    cancel || response.should_close()
}

/// No certificate is accepted unless the user explicitly selects Continue.
/// Escape, backdrop dismissal and any modal close always return Cancel.
pub fn review(
    ctx: &egui::Context,
    language: Language,
    profile_name: &str,
    endpoint: &str,
    report: &CertificateReport,
    remember: &mut bool,
) -> Option<CertificateChoice> {
    let size = dialog_size(ctx);
    let mut choice = None;
    let modal_id = egui::Id::new("certificate-review")
        .with(endpoint)
        .with(&report.certificate_sha256);
    let response = egui::Modal::new(modal_id).show(ctx, |ui| {
        let (bounds, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let mut header = region(ui, "review-header", bounds);
        title(&mut header, text(language, T::CertificateReviewTitle));
        // Measure both checkbox states with the real fonts, wrapping and button
        // sizes. Toggling cannot make the footer grow over the body this frame.
        let mut footer_height: f32 = 0.0;
        for state in [false, true] {
            footer_height = footer_height.max(measure_footer(
                ui,
                if state {
                    "review-footer-checked"
                } else {
                    "review-footer-unchecked"
                },
                bounds,
                |ui| {
                    let mut measured_remember = state;
                    let _ = review_footer(ui, language, &mut measured_remember);
                },
            ));
        }
        let footer_rect = footer_rect(bounds, footer_height);
        choice = review_footer(
            &mut region(ui, "review-footer", footer_rect),
            language,
            remember,
        );
        let body_rect = body_rect(bounds, header.min_rect().bottom(), footer_rect.top());
        let mut body = region(ui, "review-body", body_rect);
        egui::ScrollArea::vertical()
            .id_salt("certificate-review-scroll")
            .max_height(body_rect.height())
            .min_scrolled_height(0.0)
            .auto_shrink([false, false])
            .show(&mut body, |ui| {
                ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
                    ui.set_max_width(ui.available_width());
                    let warning = ui.visuals().warn_fg_color;
                    egui::Frame::new()
                        .fill(warning.gamma_multiply(0.10))
                        .stroke(egui::Stroke::new(1.0, warning.gamma_multiply(0.5)))
                        .corner_radius(7)
                        .inner_margin(12)
                        .show(ui, |ui| {
                            wrapped(ui, text(language, T::CertificateReviewWarning));
                            ui.add_space(8.0);
                            wrapped(ui, text(language, T::CertificateVerifyInstruction));
                        });
                    ui.add_space(14.0);
                    field(ui, language, T::CertificateProfile, profile_name, false);
                    field(ui, language, T::CertificateEndpoint, endpoint, false);
                    field(ui, language, T::CertificateSubject, &report.subject, false);
                    field(ui, language, T::CertificateIssuer, &report.issuer, false);
                    field(
                        ui,
                        language,
                        T::CertificateNotBefore,
                        &report.not_before,
                        false,
                    );
                    field(
                        ui,
                        language,
                        T::CertificateNotAfter,
                        &report.not_after,
                        false,
                    );
                    field(
                        ui,
                        language,
                        T::CertificateFingerprint,
                        &report.certificate_sha256,
                        true,
                    );
                    ui.separator();
                    ui.add_space(8.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(text(language, T::CertificateVerificationErrors))
                                .strong(),
                        )
                        .wrap()
                        .halign(Align::Min),
                    );
                    if report.verification_errors.is_empty() {
                        wrapped(ui, text(language, T::CertificateNoErrorDetails));
                    } else {
                        for (index, error) in report.verification_errors.iter().enumerate() {
                            ui.push_id(("certificate-verification-error", index), |ui| {
                                error_ui::error(ui, language, error);
                            });
                            ui.add_space(4.0);
                        }
                    }
                });
            });
    });
    if response.should_close() {
        Some(CertificateChoice::Cancel)
    } else {
        choice
    }
}

fn region(ui: &mut egui::Ui, id: &str, bounds: egui::Rect) -> egui::Ui {
    ui.new_child(
        egui::UiBuilder::new()
            .id_salt(id)
            .max_rect(bounds)
            .layout(egui::Layout::top_down(Align::Min)),
    )
}

fn measure_footer(
    ui: &mut egui::Ui,
    id: &str,
    bounds: egui::Rect,
    contents: impl FnOnce(&mut egui::Ui),
) -> f32 {
    let mut measure = ui.new_child(
        egui::UiBuilder::new()
            .id_salt(id)
            .max_rect(bounds)
            .layout(egui::Layout::top_down(Align::Min))
            .sizing_pass()
            .invisible(),
    );
    contents(&mut measure);
    measure.min_rect().height()
}

fn footer_rect(bounds: egui::Rect, height: f32) -> egui::Rect {
    egui::Rect::from_min_max(
        egui::pos2(bounds.left(), bounds.bottom() - height),
        bounds.right_bottom(),
    )
}

fn body_rect(bounds: egui::Rect, title_bottom: f32, footer_top: f32) -> egui::Rect {
    let top = title_bottom + 12.0;
    egui::Rect::from_min_max(
        egui::pos2(bounds.left(), top),
        egui::pos2(bounds.right(), (footer_top - 12.0).max(top)),
    )
}

fn checking_footer(ui: &mut egui::Ui, language: Language) -> bool {
    ui.separator();
    ui.add_space(8.0);
    ui.add(egui::Button::new(text(language, T::CertificateCancel)).min_size(Vec2::new(100.0, 32.0)))
        .clicked()
}

fn review_footer(
    ui: &mut egui::Ui,
    language: Language,
    remember: &mut bool,
) -> Option<CertificateChoice> {
    ui.set_max_width(ui.available_width());
    ui.separator();
    ui.add_space(8.0);
    ui.checkbox(remember, text(language, T::CertificateRemember));
    ui.add_space(6.0);
    let help = if *remember {
        T::CertificateRememberHelp
    } else {
        T::CertificateSessionTrustHelp
    };
    wrapped(ui, text(language, help));
    ui.add_space(8.0);
    let mut choice = None;
    ui.horizontal_wrapped(|ui| {
        if ui
            .add(
                egui::Button::new(text(language, T::CertificateCancel))
                    .min_size(Vec2::new(100.0, 32.0)),
            )
            .clicked()
        {
            choice = Some(CertificateChoice::Cancel);
        }
        if ui
            .add(
                egui::Button::new(text(
                    language,
                    if *remember {
                        T::CertificateRememberContinue
                    } else {
                        T::CertificateContinue
                    },
                ))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .on_hover_text(text(language, help))
            .clicked()
        {
            choice = Some(CertificateChoice::Continue);
        }
    });
    choice
}

fn dialog_size(ctx: &egui::Context) -> Vec2 {
    let viewport = ctx.content_rect().size();
    // Leave room for the native modal frame and a margin on smaller screens.
    Vec2::new(
        (viewport.x - 64.0).clamp(1.0, 620.0),
        (viewport.y - 96.0).clamp(1.0, 680.0),
    )
}

fn title(ui: &mut egui::Ui, content: &str) {
    ui.add(
        egui::Label::new(RichText::new(content).size(19.0).strong())
            .wrap()
            .halign(Align::Min),
    );
}

fn wrapped(ui: &mut egui::Ui, content: &str) {
    ui.add(egui::Label::new(content).wrap().halign(Align::Min));
}

fn field(ui: &mut egui::Ui, language: Language, label: T, content: &str, monospace: bool) {
    ui.add(
        egui::Label::new(
            RichText::new(text(language, label))
                .size(12.0)
                .color(ui.visuals().weak_text_color()),
        )
        .wrap()
        .halign(Align::Min),
    );
    value(ui, content, monospace);
    ui.add_space(10.0);
}

fn value(ui: &mut egui::Ui, content: &str, monospace: bool) {
    let mut layout = egui::text::LayoutJob::simple(
        if content.is_empty() { "—" } else { content }.to_owned(),
        if monospace {
            FontId::monospace(12.0)
        } else {
            FontId::proportional(14.0)
        },
        ui.visuals().text_color(),
        ui.available_width(),
    );
    // Long fingerprints, distinguished names and error strings keep all their
    // characters and remain copyable without stretching or horizontal overflow.
    layout.wrap.break_anywhere = true;
    ui.add(
        egui::Label::new(layout)
            .wrap()
            .halign(Align::Min)
            .selectable(true),
    );
}
