use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, B32};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

type Kem = MlKem768;
type Ek = <Kem as KemCore>::EncapsulationKey;
type Dk = <Kem as KemCore>::DecapsulationKey;
pub type Res<T> = Result<T, Box<dyn Error>>;

const MAGIC: &[u8; 4] = b"PQE3";
const EXT: &str = "pqe";
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const NONCE_LEN: usize = 7;

struct Keys {
    dk: Dk,
    ek: Ek,
    x_sk: StaticSecret,
    x_pk: PublicKey,
}

fn expand_seed(seed: &[u8]) -> Res<Keys> {
    if seed.len() != 32 {
        return Err("bad private key file (expected exactly 32 bytes)".into());
    }
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 96];
    hk.expand(b"pqe3 key derivation", &mut okm)
        .map_err(|_| "key derivation failed")?;
    let d = B32::try_from(&okm[0..32]).map_err(|_| "seed error")?;
    let z = B32::try_from(&okm[32..64]).map_err(|_| "seed error")?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&okm[64..96]);
    let (dk, ek) = Kem::generate_deterministic(&d, &z);
    let x_sk = StaticSecret::from(x);
    let x_pk = PublicKey::from(&x_sk);
    Ok(Keys { dk, ek, x_sk, x_pk })
}

fn file_key(ss_m: &[u8], ss_x: &[u8], eph_pk: &[u8], rcpt_pk: &[u8]) -> Res<[u8; 32]> {
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(eph_pk);
    ikm.extend_from_slice(rcpt_pk);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"pqe3 hybrid file key", &mut key)
        .map_err(|_| "key derivation failed")?;
    Ok(key)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = r.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

pub fn keygen(name: &str) -> Res<String> {
    let pub_path = format!("{name}.pub");
    let key_path = format!("{name}.key");
    if Path::new(&pub_path).exists() || Path::new(&key_path).exists() {
        return Err("a key with that name already exists; refusing to overwrite".into());
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let keys = expand_seed(&seed)?;

    let mut pub_bytes = Vec::new();
    pub_bytes.extend_from_slice(keys.x_pk.as_bytes());
    pub_bytes.extend_from_slice(keys.ek.as_bytes().as_slice());
    fs::write(&pub_path, &pub_bytes)?;
    fs::write(&key_path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(format!(
        "Created:\n{pub_path}  ({} bytes, use to encrypt)\n{key_path}  (32 bytes, KEEP SECRET, BACK IT UP)",
        pub_bytes.len()
    ))
}

pub fn encrypt(input: &str, pubkey: &str) -> Res<String> {
    let src = Path::new(input);
    let out = PathBuf::from(format!("{input}.{EXT}"));
    if out.exists() {
        return Err(format!("refusing to overwrite {}", out.display()).into());
    }

    let pk_bytes = fs::read(pubkey)?;
    if pk_bytes.len() < 33 {
        return Err("bad public key file".into());
    }
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&pk_bytes[..32]);
    let rcpt_x_pk = PublicKey::from(xb);
    let enc = Encoded::<Ek>::try_from(&pk_bytes[32..]).map_err(|_| "bad public key file")?;
    let ek = Ek::from_bytes(&enc);

    let mut rng = rand::thread_rng();
    let (kem_ct, ss_m) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "encapsulation failed")?;
    let eph = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pk = PublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(&rcpt_x_pk);
    if !ss_x.was_contributory() {
        return Err("invalid public key".into());
    }
    let key = file_key(
        ss_m.as_slice(),
        ss_x.as_bytes(),
        eph_pk.as_bytes(),
        rcpt_x_pk.as_bytes(),
    )?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let blob_len = 32 + kem_ct.len();
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&(blob_len as u16).to_be_bytes());
    header.extend_from_slice(eph_pk.as_bytes());
    header.extend_from_slice(kem_ct.as_slice());
    header.extend_from_slice(&nonce);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad key")?;
    let mut stream = Some(EncryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&nonce),
    ));

    let mut reader = BufReader::new(File::open(src)?);
    let mut writer = BufWriter::new(File::create(&out)?);
    writer.write_all(&header)?;

    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        let payload = Payload { msg: &buf[..n], aad: &header };
        if n < CHUNK {
            let ct = stream
                .take()
                .unwrap()
                .encrypt_last(payload)
                .map_err(|_| "encryption failed")?;
            writer.write_all(&ct)?;
            break;
        } else {
            let ct = stream
                .as_mut()
                .unwrap()
                .encrypt_next(payload)
                .map_err(|_| "encryption failed")?;
            writer.write_all(&ct)?;
        }
    }
    writer.flush()?;
    Ok(format!("Encrypted -> {}", out.display()))
}

pub fn decrypt(input: &str, privkey: &str) -> Res<String> {
    let src = Path::new(input);
    let out = if src.extension().and_then(|e| e.to_str()) == Some(EXT) {
        src.with_extension("")
    } else {
        PathBuf::from(format!("{input}.dec"))
    };
    let out = unique_path(out);

    let mut reader = BufReader::new(File::open(src)?);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("not a pqe file (or made by an older version)".into());
    }
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes)?;
    let blob_len = u16::from_be_bytes(len_bytes) as usize;
    if blob_len < 33 {
        return Err("corrupt file header".into());
    }
    let mut blob = vec![0u8; blob_len];
    reader.read_exact(&mut blob)?;
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce)?;

    let mut header = Vec::new();
    header.extend_from_slice(&magic);
    header.extend_from_slice(&len_bytes);
    header.extend_from_slice(&blob);
    header.extend_from_slice(&nonce);

    let keys = expand_seed(&fs::read(privkey)?)?;
    let mut eb = [0u8; 32];
    eb.copy_from_slice(&blob[..32]);
    let eph_pk = PublicKey::from(eb);
    let ss_x = keys.x_sk.diffie_hellman(&eph_pk);
    if !ss_x.was_contributory() {
        return Err("corrupt file header".into());
    }
    let ct = Ciphertext::<Kem>::try_from(&blob[32..]).map_err(|_| "corrupt file header")?;
    let ss_m = keys.dk.decapsulate(&ct).map_err(|_| "decapsulation failed")?;
    let key = file_key(
        ss_m.as_slice(),
        ss_x.as_bytes(),
        eph_pk.as_bytes(),
        keys.x_pk.as_bytes(),
    )?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad key")?;
    let mut stream = Some(DecryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&nonce),
    ));

    let mut writer = BufWriter::new(File::create(&out)?);
    let mut buf = vec![0u8; CHUNK + TAG];
    let fail = "decryption failed: wrong key, or the file is corrupted/tampered with";
    let result: Res<()> = (|| {
        loop {
            let n = read_full(&mut reader, &mut buf)?;
            let payload = Payload { msg: &buf[..n], aad: &header };
            if n < CHUNK + TAG {
                let pt = stream.take().unwrap().decrypt_last(payload).map_err(|_| fail)?;
                writer.write_all(&pt)?;
                break;
            } else {
                let pt = stream.as_mut().unwrap().decrypt_next(payload).map_err(|_| fail)?;
                writer.write_all(&pt)?;
            }
        }
        writer.flush()?;
        Ok(())
    })();

    if let Err(e) = result {
        drop(writer);
        let _ = fs::remove_file(&out);
        return Err(e);
    }
    Ok(format!("Decrypted -> {}", out.display()))
}

/// If `p` exists, pick "name (2).ext", "name (3).ext", ... so nothing is overwritten.
fn unique_path(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let mut n = 2;
    loop {
        let cand = dir.join(format!("{stem} ({n}){ext}"));
        if !cand.exists() {
            return cand;
        }
        n += 1;
    }
}
