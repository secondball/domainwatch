use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;

use crate::models::{CheckKind, CheckStatus, CheckResult};

pub struct AppState {
    pub target: String,
    pub input_mode: bool,
    pub scanning: bool,
    pub checks: Vec<CheckResult>,
    pub subdomains: Vec<String>,
    pub ns_records: Vec<String>,
    pub a_records: Vec<String>,
    pub subdomain_scroll: usize,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            target: String::new(),
            input_mode: true,  // start in input mode
            scanning: false,
            checks: Vec::new(),
            subdomains: Vec::new(),
            ns_records: Vec::new(),
            a_records: Vec::new(),
            subdomain_scroll: 0,
        }
    }
}

fn status_color(status: &CheckStatus) -> Color {
    match status {
        CheckStatus::Ok       => Color::Green,
        CheckStatus::Warning  => Color::Yellow,
        CheckStatus::Critical => Color::Red,
        CheckStatus::Error    => Color::Magenta,
    }
}

fn get_check<'a>(checks: &'a [CheckResult], kind: &CheckKind) -> Option<&'a CheckResult> {
    checks.iter().find(|c| &c.kind == kind)
}

fn render_check_row(label: &str, result: Option<&CheckResult>) -> Line<'static> {
    match result {
        None => Line::from(vec![
            Span::raw(format!("{:<16}", label)),
            Span::styled("PENDING", Style::default().fg(Color::DarkGray)),
        ]),
        Some(r) => Line::from(vec![
            Span::raw(format!("{:<16}", label)),
            Span::styled(
                r.status.to_string(),
                Style::default()
                    .fg(status_color(&r.status))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    }
}

pub fn draw(f: &mut Frame, state: &AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(f.area());

    // --- Input bar ---
    let input_text = if state.input_mode {
        format!(" Target: {}█   [Enter] scan  [Esc] cancel", state.target)
    } else if state.scanning {
        format!(" Scanning: {}...", state.target)
    } else {
        format!(" Target: {}   [i] edit  [r] rescan  [q] quit", state.target)
    };

    let input_style = if state.input_mode {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    let input_bar = Paragraph::new(input_text)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" CERTWATCH ")
            .style(input_style));
    f.render_widget(input_bar, root[0]);

    // --- Three columns ---
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(root[1]);

    draw_dns_column(f, state, columns[0]);
    draw_cert_column(f, state, columns[1]);
    draw_discovery_column(f, state, columns[2]);
}

fn draw_dns_column(f: &mut Frame, state: &AppState, area: Rect) {
    let spf   = get_check(&state.checks, &CheckKind::DnsSpf);
    let dmarc = get_check(&state.checks, &CheckKind::DnsDmarc);
    let mx    = get_check(&state.checks, &CheckKind::DnsMx);

    let mut lines = vec![
        Line::from(Span::styled("DNS RECORDS", Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD))),
        Line::from(""),
        render_check_row("SPF", spf),
    ];

    if let Some(c) = spf {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(render_check_row("DMARC", dmarc));

    if let Some(c) = dmarc {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(render_check_row("MX", mx));

    if let Some(c) = mx {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" DNS "));
    f.render_widget(para, area);
}

fn draw_cert_column(f: &mut Frame, state: &AppState, area: Rect) {
    let domain_expiry = get_check(&state.checks, &CheckKind::DomainExpiry);
    let tls           = get_check(&state.checks, &CheckKind::Tls);
    let hsts          = get_check(&state.checks, &CheckKind::HttpHsts);
    let redirect      = get_check(&state.checks, &CheckKind::HttpRedirect);

    let mut lines = vec![
        Line::from(Span::styled("CERTIFICATES", Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD))),
        Line::from(""),
        render_check_row("DOMAIN EXPIRY", domain_expiry),
    ];

    if let Some(c) = domain_expiry {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(render_check_row("TLS CERT", tls));

    if let Some(c) = tls {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("HTTP", Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD))));
    lines.push(Line::from(""));
    lines.push(render_check_row("HSTS", hsts));

    if let Some(c) = hsts {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::from(""));
    lines.push(render_check_row("REDIRECT", redirect));

    if let Some(c) = redirect {
        lines.push(Line::from(Span::styled(
            format!("  → {}", c.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" CERTIFICATES / HTTP "));
    f.render_widget(para, area);
}

fn draw_discovery_column(f: &mut Frame, state: &AppState, area: Rect) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(6),
        ])
        .split(area);

    // Subdomains list
    let items: Vec<ListItem> = state.subdomains
        .iter()
        .skip(state.subdomain_scroll)
        .map(|s| ListItem::new(Span::raw(s.clone())))
        .collect();

    let sub_list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(format!(" SUBDOMAINS ({}) [↑↓ scroll]", state.subdomains.len())));
    f.render_widget(sub_list, split[0]);

    // NS / A records
    let mut dns_lines = vec![
        Line::from(Span::styled("NS / A RECORDS", Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];

    for ns in &state.ns_records {
        dns_lines.push(Line::from(format!("NS  {}", ns)));
    }
    for a in &state.a_records {
        dns_lines.push(Line::from(format!("A   {}", a)));
    }

    let dns_para = Paragraph::new(dns_lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" DNS RECORDS "));
    f.render_widget(dns_para, split[1]);
}

pub fn run_ui(state: AppState) -> io::Result<AppState> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, state);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut state: AppState,
) -> io::Result<AppState> {
    loop {
        terminal.draw(|f| draw(f, &state))?;

        if let Event::Key(key) = event::read()? {
            // Fix double input on Windows — ignore release events
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match key.code {
                // Quit only when not in input mode
                KeyCode::Char('q') if !state.input_mode => {
                    state.scanning = false;
                    return Ok(state);
                }
                // Enter input mode
                KeyCode::Char('i') if !state.input_mode => {
                    state.input_mode = true;
                }
                // Rescan same target
                KeyCode::Char('r') if !state.input_mode => {
                    if !state.target.is_empty() {
                        state.scanning = true;
                        return Ok(state);
                    }
                }
                // Cancel input mode
                KeyCode::Esc => {
                    state.input_mode = false;
                }
                // Typing
                KeyCode::Char(c) if state.input_mode => {
                    state.target.push(c);
                }
                KeyCode::Backspace if state.input_mode => {
                    state.target.pop();
                }
                // Submit scan
                KeyCode::Enter if state.input_mode => {
                    if !state.target.trim().is_empty() {
                        state.input_mode = false;
                        state.scanning = true;
                        return Ok(state);
                    }
                }
                // Scroll subdomains
                KeyCode::Down => {
                    if state.subdomain_scroll + 1 < state.subdomains.len() {
                        state.subdomain_scroll += 1;
                    }
                }
                KeyCode::Up => {
                    if state.subdomain_scroll > 0 {
                        state.subdomain_scroll -= 1;
                    }
                }
                _ => {}
            }
        }
    }
}