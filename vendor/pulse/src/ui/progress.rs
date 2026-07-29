use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct ScanProgress {
    bar: ProgressBar,
}

impl ScanProgress {
    pub fn new(total: u64, quiet: bool) -> Self {
        if quiet {
            return Self {
                bar: ProgressBar::hidden(),
            };
        }

        let bar = ProgressBar::new(total);
        // Monochrome telemetry bar — white fill on dim track
        bar.set_style(
            ProgressStyle::with_template(
                "  {spinner:.white}  {msg:<8}  [{bar:36.white/bright_black}]  {pos:>5}/{len:<5}  {percent:>3}%  {eta_precise}  {per_sec}",
            )
            .unwrap()
            .progress_chars("━─ ")
            .tick_strings(&["∙", "●", "∙", "○"]),
        );
        bar.set_message("SCAN");
        bar.enable_steady_tick(Duration::from_millis(120));

        Self { bar }
    }

    pub fn set(&self, n: u64) {
        self.bar.set_position(n);
    }

    pub fn finish(&self) {
        self.bar.finish_and_clear();
    }
}
