//! pqe command-line tool. Run `pqe` with no arguments for usage.

use std::env;
use std::process;

const USAGE: &str = "pqe - post-quantum file encryption

Usage:
  pqe keygen <name> [--password]                      make <name>.pub, <name>.vk, <name>.key
  pqe encrypt <file-or-folder> <name.pub> [--sign <me.key>]
  pqe decrypt <file.pqe> <name.key> [--verify <sender.vk>]
  pqe fingerprint <file.pub|file.vk>                  short code to compare with the owner
  pqe export-vk <name.key>                            make <name>.vk for a key made by v0.1

Notes:
  --password   protects the new private key with a password (asked twice)
  --sign       signs the file with your key, so the receiver can prove who made it
  --verify     refuses to open the file unless it carries a valid signature from that sender
  Password-protected keys ask for their password automatically.";

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    if let Some(i) = args.iter().position(|a| a == name) {
        if i + 1 < args.len() {
            let v = args.remove(i + 1);
            args.remove(i);
            return Some(v);
        }
        eprintln!("{name} needs a value\n\n{USAGE}");
        process::exit(2);
    }
    None
}

fn ask(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Could not read the password: {e}");
        process::exit(1);
    })
}

fn password_if_locked(key_path: &str, what: &str) -> Option<String> {
    if pqe::key_is_protected(key_path) {
        Some(ask(&format!("Password for {what}: ")))
    } else {
        None
    }
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let protect = take_flag(&mut args, "--password");
    let sign = take_opt(&mut args, "--sign");
    let verify = take_opt(&mut args, "--verify");

    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", name] => {
            let pw = if protect {
                let a = ask("New password: ");
                let b = ask("Repeat password: ");
                if a != b {
                    eprintln!("The passwords do not match.");
                    process::exit(1);
                }
                Some(a)
            } else {
                None
            };
            pqe::keygen(name, pw.as_deref())
        }
        ["encrypt", file, pubkey] => {
            let opts = sign.as_ref().map(|k| pqe::SignOpts {
                key_path: k.clone(),
                password: password_if_locked(k, "your signing key"),
            });
            pqe::encrypt(file, pubkey, opts)
        }
        ["decrypt", file, key] => {
            let pw = password_if_locked(key, "your private key");
            pqe::decrypt(file, key, pw.as_deref(), verify.as_deref())
        }
        ["fingerprint", path] => pqe::fingerprint(path),
        ["export-vk", key] => {
            let pw = password_if_locked(key, "your private key");
            pqe::export_vk(key, pw.as_deref())
        }
        _ => {
            eprintln!("{USAGE}");
            process::exit(2);
        }
    };

    match result {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}