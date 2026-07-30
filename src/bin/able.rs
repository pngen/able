fn main() {
    eprintln!(
        "{} is a library crate; integrate its ExecutionGate into a host application",
        env!("CARGO_PKG_NAME")
    );
    std::process::exit(2);
}
