use std::io::IsTerminal;
use std::sync::OnceLock;

fn tty() -> bool {
    static TTY: OnceLock<bool> = OnceLock::new();
    *TTY.get_or_init(|| std::io::stdout().is_terminal())
}

fn paint(code: &str, text: &str) -> String {
    if tty() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn banner(text: &str) {
    println!("\n{}", paint("1;36", &format!("=== {text} ===")));
}

pub fn step(text: &str) {
    println!("\n{} {}", paint("1;34", "▶"), paint("1", text));
}

pub fn numbered_step(index: usize, total: usize, text: &str) {
    println!(
        "\n{} {}",
        paint("1;34", &format!("▶ step {index}/{total}")),
        paint("1", text)
    );
}

pub fn explain(asks: &str, how: &str) {
    println!("    {} {}", paint("2;36", "asks:"), paint("2", asks));
    println!("    {} {}", paint("2;36", "how: "), paint("2", how));
}

pub fn ok(text: &str) {
    println!("  {} {text}", paint("1;32", "✓"));
}

pub fn warn(text: &str) {
    println!("  {} {text}", paint("1;33", "!"));
}

pub fn fail(text: &str) {
    println!("  {} {text}", paint("1;31", "✗"));
}

pub fn detail(text: &str) {
    println!("    {}", paint("2", text));
}

pub fn item(text: &str) {
    println!("      {} {}", paint("2", "·"), paint("2", text));
}

pub fn nested_item(text: &str, depth: usize) {
    let padding = "  ".repeat(depth);

    println!("      {}{} {}", padding, paint("2", "·"), paint("2", text));
}

pub fn field(key: &str, value: &str) {
    println!("    {} {value}", paint("2", &format!("{key:<18}")));
}

pub fn raw(text: &str) {
    println!("      {}", paint("2", text));
}

pub fn hint(text: &str) {
    println!("\n{} {}", paint("1;35", "→"), text);
}
