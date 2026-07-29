use crate::scanner::{
    scan_with_events, PortResult, ScanConfig, ScanEvent, ScanStats, Target,
};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Sparkline, Table, TableState, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use std::collections::{HashSet, VecDeque};
use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct TuiScanMeta {
    pub target_label: String,
    pub port_label: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub protocols: String,
    pub banner: bool,
    pub syn: bool,
    pub adaptive: bool,
    pub host_first: bool,
    pub host_parallel: usize,
    pub syn_retries: u8,
}

struct App {
    meta: TuiScanMeta,
    total: usize,
    done: usize,
    open_ports: Vec<PortResult>,
    hosts_done: usize,
    hosts_with_open: HashSet<String>,
    last_host: String,
    rate_history: VecDeque<u64>,
    last_rate_sample: Instant,
    last_done: usize,
    current_rate: f64,
    finished: bool,
    cancelled: bool,
    table_state: TableState,
    started: Instant,
    status: String,
    /// Live filter string (`/` to edit)
    filter: String,
    filter_mode: bool,
}

impl App {
    fn new(meta: TuiScanMeta, total: usize) -> Self {
        Self {
            meta,
            total,
            done: 0,
            open_ports: Vec::new(),
            hosts_done: 0,
            hosts_with_open: HashSet::new(),
            last_host: String::new(),
            rate_history: VecDeque::from(vec![0; 56]),
            last_rate_sample: Instant::now(),
            last_done: 0,
            current_rate: 0.0,
            finished: false,
            cancelled: false,
            table_state: TableState::default(),
            started: Instant::now(),
            status: "scanning…".into(),
            filter: String::new(),
            filter_mode: false,
        }
    }

    fn on_progress(&mut self, done: usize, total: usize) {
        self.done = done;
        self.total = total;
        self.sample_rate();
    }

    fn on_open(&mut self, r: PortResult) {
        self.hosts_with_open.insert(r.ip.clone());
        self.open_ports.push(r);
        self.open_ports
            .sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
        // follow latest when not filtering / no selection
        if !self.filter_mode {
            let visible = self.visible_indices();
            if let Some(&idx) = visible.last() {
                self.table_state.select(Some(idx));
            } else if self.table_state.selected().is_none() && !self.open_ports.is_empty() {
                self.table_state.select(Some(0));
            }
        }
    }

    fn on_host_done(&mut self, ip: String, open: usize) {
        self.hosts_done = self.hosts_done.saturating_add(1);
        self.last_host = ip.clone();
        self.status = format!("host {ip} · {open} open · {} hosts done", self.hosts_done);
    }

    fn sample_rate(&mut self) {
        let elapsed = self.last_rate_sample.elapsed().as_secs_f64();
        if elapsed >= 0.2 {
            let delta = self.done.saturating_sub(self.last_done) as f64;
            self.current_rate = delta / elapsed;
            self.rate_history.pop_front();
            self.rate_history.push_back(self.current_rate as u64);
            self.last_done = self.done;
            self.last_rate_sample = Instant::now();
        }
    }

    fn progress_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.done as f64 / self.total as f64
        }
    }

    /// Indices into open_ports that match filter.
    fn visible_indices(&self) -> Vec<usize> {
        let q = self.filter.to_ascii_lowercase();
        if q.is_empty() {
            return (0..self.open_ports.len()).collect();
        }
        self.open_ports
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let blob = format!(
                    "{} {} {} {} {}",
                    r.ip,
                    r.port,
                    r.service,
                    r.protocol.as_str(),
                    r.banner.as_deref().unwrap_or("")
                )
                .to_ascii_lowercase();
                blob.contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn select_next(&mut self) {
        let vis = self.visible_indices();
        if vis.is_empty() {
            return;
        }
        let cur = self.table_state.selected().unwrap_or(vis[0]);
        let pos = vis.iter().position(|&i| i == cur).unwrap_or(0);
        let next = vis[(pos + 1).min(vis.len() - 1)];
        self.table_state.select(Some(next));
    }

    fn select_prev(&mut self) {
        let vis = self.visible_indices();
        if vis.is_empty() {
            return;
        }
        let cur = self.table_state.selected().unwrap_or(vis[0]);
        let pos = vis.iter().position(|&i| i == cur).unwrap_or(0);
        let prev = vis[pos.saturating_sub(1)];
        self.table_state.select(Some(prev));
    }
}

pub async fn run_tui_scan(
    targets: Vec<Target>,
    ports: Vec<u16>,
    config: ScanConfig,
    meta: TuiScanMeta,
) -> Result<(Vec<PortResult>, Arc<ScanStats>)> {
    let total = targets.len() * ports.len() * config.protocols.len().max(1);

    let (tx, mut rx) = mpsc::unbounded_channel::<ScanEvent>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_bg = cancel.clone();

    let scan_handle = tokio::spawn(scan_with_events(
        targets,
        ports,
        config,
        tx,
        cancel_bg,
    ));

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = ratatui::init();

    let mut app = App::new(meta, total);
    let mut all_results = Vec::new();
    let mut stats = Arc::new(ScanStats::new(total));

    let ui_result = run_ui_loop(&mut terminal, &mut app, &mut rx, &cancel).await;

    ratatui::restore();
    disable_raw_mode()?;
    execute!(stdout, LeaveAlternateScreen)?;

    ui_result?;

    if let Ok((results, s)) = scan_handle.await {
        all_results = results;
        stats = s;
    }

    if app.cancelled {
        cancel.store(true, Ordering::Relaxed);
    }

    Ok((all_results, stats))
}

async fn run_ui_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let tick = Duration::from_millis(50);

    loop {
        terminal.draw(|f| draw(f, app))?;

        while let Ok(ev) = rx.try_recv() {
            match ev {
                ScanEvent::Progress { done, total } => app.on_progress(done, total),
                ScanEvent::Open(r) => app.on_open(r),
                ScanEvent::HostDone { ip, open, .. } => app.on_host_done(ip, open),
                ScanEvent::Finished => {
                    app.finished = true;
                    app.status = if app.cancelled {
                        "cancelled — q to exit".into()
                    } else {
                        format!(
                            "complete · {} open · {} hosts · q exit",
                            app.open_ports.len(),
                            app.hosts_with_open.len()
                        )
                    };
                }
            }
        }

        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.filter_mode {
                        match key.code {
                            KeyCode::Esc => {
                                app.filter_mode = false;
                            }
                            KeyCode::Enter => {
                                app.filter_mode = false;
                            }
                            KeyCode::Backspace => {
                                app.filter.pop();
                            }
                            KeyCode::Char(c) => {
                                app.filter.push(c);
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                if app.finished {
                                    break;
                                }
                                app.cancelled = true;
                                app.status = "cancelling…".into();
                                cancel.store(true, Ordering::Relaxed);
                            }
                            KeyCode::Char('Q') => {
                                cancel.store(true, Ordering::Relaxed);
                                app.cancelled = true;
                                break;
                            }
                            KeyCode::Char('/') => {
                                app.filter_mode = true;
                            }
                            KeyCode::Char('c') if !app.filter.is_empty() => {
                                app.filter.clear();
                            }
                            KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                            KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                            KeyCode::PageDown => {
                                for _ in 0..10 {
                                    app.select_next();
                                }
                            }
                            KeyCode::PageUp => {
                                for _ in 0..10 {
                                    app.select_prev();
                                }
                            }
                            KeyCode::Home => {
                                if let Some(&i) = app.visible_indices().first() {
                                    app.table_state.select(Some(i));
                                }
                            }
                            KeyCode::End => {
                                if let Some(&i) = app.visible_indices().last() {
                                    app.table_state.select(Some(i));
                                }
                            }
                            KeyCode::Enter if app.finished => break,
                            _ => {}
                        }
                    }
                }
            }
        }

        app.sample_rate();

        if app.finished {
            tokio::time::sleep(Duration::from_millis(16)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

fn draw(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, root[0], app);
    draw_meta(f, root[1], app);
    draw_progress(f, root[2], app);
    draw_table(f, root[3], app);
    draw_sparkline(f, root[4], app);
    draw_footer(f, root[5], app);

    if app.filter_mode {
        draw_filter_popup(f, app);
    }
}

// ── Neon glass palette ──────────────────────────────────────────────
fn pink() -> Color {
    Color::Rgb(255, 46, 158)
}
fn cyan() -> Color {
    Color::Rgb(51, 240, 255)
}
fn ok() -> Color {
    Color::Rgb(57, 255, 136)
}
fn void_bg() -> Color {
    Color::Rgb(12, 4, 18)
}

fn border_dim() -> Style {
    Style::default().fg(Color::Rgb(90, 40, 70))
}
fn border_hot() -> Style {
    Style::default().fg(pink())
}
fn fg_white() -> Style {
    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
}
fn fg_dim() -> Style {
    Style::default().fg(Color::Rgb(160, 110, 140))
}
fn fg_ok() -> Style {
    Style::default().fg(ok())
}
fn fg_cyan() -> Style {
    Style::default().fg(cyan())
}
fn fg_pink() -> Style {
    Style::default().fg(pink()).add_modifier(Modifier::BOLD)
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let status_style = if app.finished {
        fg_ok()
    } else if app.cancelled {
        Style::default().fg(Color::Rgb(255, 80, 100))
    } else {
        fg_cyan()
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled("  PULSE  ", fg_pink()),
        Span::styled("MISSION CONTROL", fg_dim()),
        Span::styled("  ·  ", fg_dim()),
        Span::styled(app.status.clone(), status_style),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_hot())
            .title(Span::styled(" SIGNAL ", fg_pink())),
    );
    f.render_widget(title, area);
}

fn draw_meta(f: &mut Frame, area: Rect, app: &App) {
    let elapsed = app.started.elapsed().as_secs_f64();
    let mut engine = format!(
        "{}c  {}ms  {elapsed:.1}s",
        app.meta.concurrency, app.meta.timeout_ms
    );
    if app.meta.adaptive {
        engine.push_str("  · ADAPT");
    }
    if app.meta.host_parallel > 0 {
        engine.push_str(&format!("  · HOST×{}", app.meta.host_parallel));
    } else if app.meta.host_first {
        engine.push_str("  · HOST-FIRST");
    }
    if app.meta.syn {
        engine.push_str("  · SYN");
        if app.meta.syn_retries > 0 {
            engine.push_str(&format!("×{}", app.meta.syn_retries + 1));
        }
    } else if app.meta.banner {
        engine.push_str("  · BANNER");
    }

    let text = vec![
        Line::from(vec![
            Span::styled(" TARGET   ", fg_dim()),
            Span::styled(app.meta.target_label.clone(), fg_white()),
        ]),
        Line::from(vec![
            Span::styled(" PORTS    ", fg_dim()),
            Span::styled(
                app.meta.port_label.clone(),
                Style::default().fg(Color::White),
            ),
            Span::styled("  ·  ", fg_dim()),
            Span::styled(app.meta.protocols.clone(), fg_cyan()),
        ]),
        Line::from(vec![
            Span::styled(" ENGINE   ", fg_dim()),
            Span::styled(engine, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" HOSTS    ", fg_dim()),
            Span::styled(
                format!(
                    "{} done  ·  {} with open  ·  last {}",
                    app.hosts_done,
                    app.hosts_with_open.len(),
                    if app.last_host.is_empty() {
                        "—"
                    } else {
                        &app.last_host
                    }
                ),
                fg_cyan(),
            ),
        ]),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_dim())
            .title(Span::styled(" TELEMETRY ", fg_pink())),
    );
    f.render_widget(p, area);
}

fn draw_progress(f: &mut Frame, area: Rect, app: &App) {
    let ratio = app.progress_ratio().clamp(0.0, 1.0);
    let label = format!(
        "{}/{}  {:.0}%   OPEN {}   HOSTS {}   {:.0} pps",
        app.done,
        app.total,
        ratio * 100.0,
        app.open_ports.len(),
        app.hosts_with_open.len(),
        app.current_rate
    );

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_hot())
                .title(Span::styled(" PROGRESS ", fg_pink())),
        )
        .gauge_style(
            Style::default()
                .fg(pink())
                .bg(void_bg())
                .add_modifier(Modifier::BOLD),
        )
        .ratio(ratio)
        .label(Span::styled(label, Style::default().fg(Color::White)));

    f.render_widget(gauge, area);
}

fn draw_table(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["PROTO", "HOST", "PORT", "SERVICE", "LATENCY", "BANNER"])
        .style(fg_pink())
        .bottom_margin(0);

    let vis = app.visible_indices();
    let rows = vis.iter().filter_map(|&i| app.open_ports.get(i)).map(|r| {
        let lat = r
            .latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "—".into());
        let banner = r.banner.as_deref().unwrap_or("—");
        Row::new(vec![
            Cell::from(r.protocol.as_str().to_uppercase()).style(fg_dim()),
            Cell::from(r.ip.as_str()).style(Style::default().fg(Color::White)),
            Cell::from(r.port.to_string()).style(fg_pink()),
            Cell::from(r.service.as_str()).style(fg_cyan()),
            Cell::from(lat).style(fg_dim()),
            Cell::from(banner).style(fg_dim()),
        ])
    });

    let widths = [
        Constraint::Length(6),
        Constraint::Length(16),
        Constraint::Length(7),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Min(10),
    ];

    let filter_tag = if app.filter.is_empty() {
        String::new()
    } else {
        format!("  /{}  ", app.filter)
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_dim())
                .title(Span::styled(
                    format!(
                        " OPEN  ({}/{}) {} ",
                        vis.len(),
                        app.open_ports.len(),
                        filter_tag
                    ),
                    fg_ok(),
                )),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 10, 30))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    // Map selected open_ports index for highlight — Table uses visual row index
    let mut state = TableState::default();
    if let Some(sel) = app.table_state.selected() {
        if let Some(vis_pos) = vis.iter().position(|&i| i == sel) {
            state.select(Some(vis_pos));
        }
    }

    f.render_stateful_widget(table, area, &mut state);
}

fn draw_sparkline(f: &mut Frame, area: Rect, app: &App) {
    let data: Vec<u64> = app.rate_history.iter().copied().collect();
    let max = data.iter().copied().max().unwrap_or(1).max(1);

    let spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_dim())
                .title(Span::styled(
                    format!(" THROUGHPUT  peak {max} pps · now {:.0} ", app.current_rate),
                    fg_cyan(),
                )),
        )
        .data(&data)
        .max(max)
        .style(Style::default().fg(cyan()));

    f.render_widget(spark, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let help = if app.filter_mode {
        "  FILTER  type…  ENTER/ESC apply  BACKSPACE erase"
    } else if app.finished {
        "  Q/ESC exit   / filter   C clear filter   ↑↓ j/k  PgUp/PgDn  Home/End"
    } else {
        "  Q cancel   Shift+Q abort   / filter   ↑↓ scroll   PgUp/PgDn"
    };
    let p = Paragraph::new(help)
        .style(fg_dim())
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_filter_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 3, f.area());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_hot())
        .title(Span::styled(" FILTER ", fg_pink()))
        .style(Style::default().bg(void_bg()));
    let inner = block.inner(area);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    let text = format!("/{}", app.filter);
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::White)),
        inner,
    );
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let width = (r.width as u32 * percent_x as u32 / 100).max(10) as u16;
    let height = height.min(r.height);
    let x = r.x + r.width.saturating_sub(width) / 2;
    let y = r.y + r.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}
