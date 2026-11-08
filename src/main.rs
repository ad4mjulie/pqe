use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [_, "keygen", name] => pqe::keygen(name),
        [_, "encrypt", file, pubkey] => pqe::encrypt(file, pubkey),
        [_, "decrypt", file, key] => pqe::decrypt(file, key),
        _ => {
            eprintln!(
                "Usage:\n  pqe keygen <name>\n  pqe encrypt <file> <name.pub>\n  pqe decrypt <file.pqe> <name.key>"
            );
            std::process::exit(2);
        }
    };
    match result {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}
