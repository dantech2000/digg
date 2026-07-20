fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match digg::run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            digg::eprint_error(&e.to_string());
            std::process::exit(e.exit_code());
        }
    }
}
