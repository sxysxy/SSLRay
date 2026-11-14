//! Certificate review UI only. Network actions and trust state belong to the caller.
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
        ui.set_width(size.x);
        egui::ScrollArea::vertical()
            .id_salt("certificate-checking-scroll")
            .max_height(size.y)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
                    title(ui, text(language, T::CertificateCheckingTitle));
                    ui.add_space(10.0);
                    ui.spinner();
                    wrapped(ui, text(language, T::CertificateCheckingHelp));
                    ui.add_space(14.0);
                    field(ui, language, T::CertificateProfile, profile_name, false);
                    field(ui, language, T::CertificateEndpoint, endpoint, false);
                    ui.add_space(8.0);
                    cancel = ui
                        .add(
                            egui::Button::new(text(language, T::CertificateCancel))
                                .min_size(Vec2::new(100.0, 32.0)),
                        )
                        .clicked();
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
        ui.set_width(size.x);
        egui::ScrollArea::vertical()
            .id_salt("certificate-review-scroll")
            .max_height(size.y)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::top_down(Align::Min), |ui| {
                    title(ui, text(language, T::CertificateReviewTitle));
                    ui.add_space(12.0);
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
                        for error in &report.verification_errors {
                            value(ui, error, false);
                            ui.add_space(4.0);
                        }
                    }
                    ui.add_space(12.0);
                    ui.checkbox(remember, text(language, T::CertificateRemember));
                    ui.add_space(6.0);
                    wrapped(ui, text(language, T::CertificateRememberHelp));
                    ui.add_space(12.0);
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
                            .on_hover_text(text(
                                language,
                                if *remember {
                                    T::CertificateRememberHelp
                                } else {
                                    T::CertificateSessionTrustHelp
                                },
                            ))
                            .clicked()
                        {
                            choice = Some(CertificateChoice::Continue);
                        }
                    });
                });
            });
    });
    if response.should_close() {
        Some(CertificateChoice::Cancel)
    } else {
        choice
    }
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
