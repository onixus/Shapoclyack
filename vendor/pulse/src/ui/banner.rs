use owo_colors::OwoColorize;

/// Minimal wordmark — black-void / white-signal (SpaceX · xAI energy).
pub fn print_banner() {
    // Clean geometric wordmark, no rainbow cyber-gunk.
    let mark = r#"
  ╔══════════════════════════════════════════════════╗
  ║                                                  ║
  ║   P U L S E                                      ║
  ║   NETWORK  ·  SIGNAL  ·  TRUTH                   ║
  ║                                                  ║
  ╚══════════════════════════════════════════════════╝"#;

    println!("{}", mark.white().bold());
    println!(
        "  {}  {}  {}  {}\n",
        "v0.2".bright_black(),
        "·".bright_black(),
        "async tcp/udp".bright_black(),
        "·  zero fluff".bright_black()
    );
}
