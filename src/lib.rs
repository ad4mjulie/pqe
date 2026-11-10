//! pqe core.
//!
//! Encryption: hybrid ML-KEM-768 + X25519 key exchange -> HKDF-SHA256 -> streaming AES-256-GCM.
//! Signatures: hybrid Ed25519 + ML-DSA-65 over a SHA-512 digest of the whole ciphertext.
//! Private keys: a 32-byte seed, optionally sealed with Argon2id + AES-256-GCM.
//! Folders: packed into a tar archive and encrypted like a file.
//!
//! Key files made by `keygen("name", ..)`:
//!   name.pub  encryption public key  (X25519 32 B || ML-KEM-768 1184 B)
//!   name.vk   signature verifying key (Ed25519 32 B || ML-DSA-65 1952 B)
//!   name.key  private seed (32 B, or 92 B when password-protected); derives everything above

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, Verifier as _,
    VerifyingKey as EdVerifyingKey,
};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedVerifyingKey as MlEncodedVk, Keypair as _, MlDsa65, Signature as MlSignature,
    Signer as _, SigningKey as MlSigningKey, Verifier as _, VerifyingKey as MlVerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

type Kem = MlKem768;
type Ek = <Kem as KemCore>::EncapsulationKey;
type Dk = <Kem as KemCore>::DecapsulationKey;
pub type Res<T> = Result<T, Box<dyn Error>>;

const MAGIC3: &[u8; 4] = b"PQE3"; // v0.1 files (still readable)
const MAGIC4: &[u8; 4] = b"PQE4";
const PW_MAGIC: &[u8; 4] = b"PQK1";
const EXT: &str = "pqe";
const CHUNK: usize = 1 << 20; // 1 MiB plaintext per chunk
const TAG: usize = 16;
const NONCE_LEN: usize = 7;

const ED_SIG_LEN: usize = 64;
const ML_SIG_LEN: usize = 3309;
const SIG_LEN: usize = ED_SIG_LEN + ML_SIG_LEN;
const ED_VK_LEN: usize = 32;
const ML_VK_LEN: usize = 1952;
const VK_LEN: usize = ED_VK_LEN + ML_VK_LEN;

const KIND_FILE: u8 = 0;
const KIND_DIR: u8 = 1;
const SIG_LABEL: &[u8] = b"pqe4 signature v1";
const BAD_SIG: &str = "SIGNATURE INVALID: this file was not signed by that key, or it was modified";

// Argon2id settings for password-protected keys.
const KDF_M_KIB: u32 = 65536; // 64 MiB
const KDF_T: u32 = 3;
const KDF_P: u32 = 1;

/// Sign a file with the identity stored in `key_path`.
pub struct SignOpts {
    pub key_path: String,
    pub password: Option<String>,
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

struct Keys {
    dk: Dk,
    ek: Ek,
    x_sk: StaticSecret,
    x_pk: PublicKey,
}

/// Rebuild the encryption key pair from the 32-byte private seed.
fn expand_seed(seed: &[u8]) -> Res<Keys> {
    if seed.len() != 32 {
        return Err("bad private key (expected exactly 32 bytes)".into());
    }
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 96];
    hk.expand(b"pqe3 key derivation", &mut okm)
        .map_err(|_| "key derivation failed")?;
    let d = ml_kem::B32::try_from(&okm[0..32]).map_err(|_| "seed error")?;
    let z = ml_kem::B32::try_from(&okm[32..64]).map_err(|_| "seed error")?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&okm[64..96]);
    let (dk, ek) = Kem::generate_deterministic(&d, &z);
    let x_sk = StaticSecret::from(x);
    let x_pk = PublicKey::from(&x_sk);
    Ok(Keys { dk, ek, x_sk, x_pk })
}

struct SignId {
    ed: EdSigningKey,
    ml: MlSigningKey<MlDsa65>,
    vk: Vec<u8>, // Ed25519 vk (32) || ML-DSA-65 vk (1952)
}

/// Derive the signing identity from the same 32-byte seed (separate HKDF label).
fn derive_signing(seed: &[u8]) -> Res<SignId> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 64];
    hk.expand(b"pqe4 signing key derivation", &mut okm)
        .map_err(|_| "key derivation failed")?;
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(&okm[..32]);
    let mut ml_seed = [0u8; 32];
    ml_seed.copy_from_slice(&okm[32..]);

    let ed = EdSigningKey::from_bytes(&ed_seed);
    let ml = MlSigningKey::<MlDsa65>::from_seed(&ml_dsa::B32::from(ml_seed));

    let mut vk = Vec::with_capacity(VK_LEN);
    vk.extend_from_slice(ed.verifying_key().as_bytes());
    vk.extend_from_slice(ml.verifying_key().encode().as_slice());
    if vk.len() != VK_LEN {
        return Err("unexpected verifying key size".into());
    }
    Ok(SignId { ed, ml, vk })
}

/// Both signatures must verify.
fn verify_sig(vk: &[u8], digest: &[u8], sig: &[u8]) -> Res<()> {
    if vk.len() != VK_LEN {
        return Err("bad sender key file (wrong size)".into());
    }
    if sig.len() != SIG_LEN {
        return Err(BAD_SIG.into());
    }
    let mut edb = [0u8; 32];
    edb.copy_from_slice(&vk[..ED_VK_LEN]);
    let edvk = EdVerifyingKey::from_bytes(&edb).map_err(|_| "bad sender key file")?;
    let mut sb = [0u8; 64];
    sb.copy_from_slice(&sig[..ED_SIG_LEN]);
    edvk.verify(digest, &EdSignature::from_bytes(&sb))
        .map_err(|_| BAD_SIG)?;

    let enc = MlEncodedVk::<MlDsa65>::try_from(&vk[ED_VK_LEN..]).map_err(|_| "bad sender key file")?;
    let mlvk = MlVerifyingKey::<MlDsa65>::decode(&enc);
    let mls = MlSignature::<MlDsa65>::try_from(&sig[ED_SIG_LEN..]).map_err(|_| BAD_SIG)?;
    mlvk.verify(digest, &mls).map_err(|_| BAD_SIG)?;
    Ok(())
}

fn fmt_fp(h: &[u8]) -> String {
    let hex: String = h.iter().take(16).map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Short fingerprint of a .pub or .vk file. Compare it with the owner over another channel.
pub fn fingerprint(path: &str) -> Res<String> {
    let bytes = fs::read(path)?;
    Ok(fmt_fp(&Sha256::digest(&bytes)))
}

// ---------------------------------------------------------------------------
// Password-protected private keys (PQK1)
// layout: "PQK1" | m u32 | t u32 | p u32 | salt 16 | nonce 12 | AES-GCM(seed) 48
// ---------------------------------------------------------------------------

fn kdf(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Res<[u8; 32]> {
    let params = Params::new(m, t, p, Some(32)).map_err(|_| "bad key-derivation settings")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| "password hashing failed")?;
    Ok(out)
}

fn seal_seed(seed: &[u8; 32], password: &str) -> Res<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = kdf(password, &salt, KDF_M_KIB, KDF_T, KDF_P)?;

    let mut hdr = Vec::with_capacity(32);
    hdr.extend_from_slice(PW_MAGIC);
    hdr.extend_from_slice(&KDF_M_KIB.to_be_bytes());
    hdr.extend_from_slice(&KDF_T.to_be_bytes());
    hdr.extend_from_slice(&KDF_P.to_be_bytes());
    hdr.extend_from_slice(&salt);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad key")?;
    let ct = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload { msg: seed.as_slice(), aad: &hdr },
        )
        .map_err(|_| "could not protect the key")?;

    let mut out = hdr;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_seed(b: &[u8], password: &str) -> Res<[u8; 32]> {
    if b.len() != 92 {
        return Err("corrupt protected key file".into());
    }
    let m = u32::from_be_bytes(b[4..8].try_into().map_err(|_| "corrupt key file")?);
    let t = u32::from_be_bytes(b[8..12].try_into().map_err(|_| "corrupt key file")?);
    let p = u32::from_be_bytes(b[12..16].try_into().map_err(|_| "corrupt key file")?);
    if m == 0 || m > (1 << 20) || t == 0 || t > 20 || p == 0 || p > 16 {
        return Err("corrupt protected key file (bad settings)".into());
    }
    let key = kdf(password, &b[16..32], m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad key")?;
    let pt = cipher
        .decrypt(
            GenericArray::from_slice(&b[32..44]),
            Payload { msg: &b[44..], aad: &b[..32] },
        )
        .map_err(|_| "wrong password (or the key file is damaged)")?;
    if pt.len() != 32 {
        return Err("corrupt protected key file".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pt);
    Ok(seed)
}

/// True if the private key file needs a password.
pub fn key_is_protected(path: &str) -> bool {
    File::open(path)
        .ok()
        .and_then(|mut f| {
            let mut b = [0u8; 4];
            f.read_exact(&mut b).ok()?;
            Some(&b == PW_MAGIC)
        })
        .unwrap_or(false)
}

fn load_seed(path: &str, password: Option<&str>) -> Res<[u8; 32]> {
    let b = fs::read(path)?;
    if b.len() >= 4 && &b[..4] == PW_MAGIC {
        let pw = password.ok_or("this key is password-protected: a password is required")?;
        return open_seed(&b, pw);
    }
    if b.len() == 32 {
        let mut s = [0u8; 32];
        s.copy_from_slice(&b);
        return Ok(s);
    }
    Err("bad private key file".into())
}

fn write_private(path: &str, bytes: &[u8]) -> Res<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Creates `<name>.pub`, `<name>.vk` and `<name>.key`.
pub fn keygen(name: &str, password: Option<&str>) -> Res<String> {
    let pub_path = format!("{name}.pub");
    let vk_path = format!("{name}.vk");
    let key_path = format!("{name}.key");
    if [&pub_path, &vk_path, &key_path].iter().any(|p| Path::new(p.as_str()).exists()) {
        return Err("a key with that name already exists; refusing to overwrite".into());
    }
    if let Some(p) = password {
        if p.is_empty() {
            return Err("the password must not be empty".into());
        }
    }

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let keys = expand_seed(&seed)?;
    let sign = derive_signing(&seed)?;

    let mut pub_bytes = Vec::new();
    pub_bytes.extend_from_slice(keys.x_pk.as_bytes());
    pub_bytes.extend_from_slice(keys.ek.as_bytes().as_slice());

    let key_bytes = match password {
        Some(p) => seal_seed(&seed, p)?,
        None => seed.to_vec(),
    };

    fs::write(&pub_path, &pub_bytes)?;
    fs::write(&vk_path, &sign.vk)?;
    write_private(&key_path, &key_bytes)?;

    Ok(format!(
        "Created:\n{pub_path}  ({} bytes, people encrypt to this)\n{vk_path}  ({} bytes, people verify your signatures with this)\n{key_path}  ({} bytes{}, KEEP SECRET, BACK IT UP)\nEncryption fingerprint: {}\nSigning fingerprint:    {}\nShare the fingerprints over a second channel so others can check your keys.",
        pub_bytes.len(),
        sign.vk.len(),
        key_bytes.len(),
        if password.is_some() { ", password-protected" } else { "" },
        fmt_fp(&Sha256::digest(&pub_bytes)),
        fmt_fp(&Sha256::digest(&sign.vk)),
    ))
}

/// Writes `<key>.vk` from an existing private key (needed for keys made before signing existed).
pub fn export_vk(key_path: &str, password: Option<&str>) -> Res<String> {
    let out = Path::new(key_path).with_extension("vk");
    if out.exists() {
        return Err(format!("{} already exists; refusing to overwrite", out.display()).into());
    }
    let seed = load_seed(key_path, password)?;
    let sign = derive_signing(&seed)?;
    fs::write(&out, &sign.vk)?;
    Ok(format!(
        "Created {} ({} bytes)\nSigning fingerprint: {}",
        out.display(),
        sign.vk.len(),
        fmt_fp(&Sha256::digest(&sign.vk))
    ))
}

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------
// PQE4: "PQE4" | kind u8 | sig_len u16 | [signer fingerprint 32 B if sig_len>0]
//       | blob_len u16 | blob (X25519 ephemeral 32 B || ML-KEM ct) | nonce 7 B
//       | AES-GCM chunks ... | [signature: Ed25519 64 B || ML-DSA-65 3309 B]
// PQE3 (v0.1): "PQE3" | blob_len u16 | blob | nonce 7 B | AES-GCM chunks ...
// The whole header is authenticated as AAD on every chunk.

struct Header {
    raw: Vec<u8>,
    kind: u8,
    sig_len: usize,
    signer_fp: Option<[u8; 32]>,
    blob: Vec<u8>,
    nonce: [u8; NONCE_LEN],
}

fn read_header<R: Read>(r: &mut R) -> Res<Header> {
    let mut raw = Vec::new();
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    raw.extend_from_slice(&magic);

    let (kind, sig_len, signer_fp) = if &magic == MAGIC4 {
        let mut kb = [0u8; 1];
        r.read_exact(&mut kb)?;
        raw.extend_from_slice(&kb);
        let mut sl = [0u8; 2];
        r.read_exact(&mut sl)?;
        raw.extend_from_slice(&sl);
        let sig_len = u16::from_be_bytes(sl) as usize;
        let fp = if sig_len > 0 {
            let mut f = [0u8; 32];
            r.read_exact(&mut f)?;
            raw.extend_from_slice(&f);
            Some(f)
        } else {
            None
        };
        if kb[0] > KIND_DIR {
            return Err("unsupported file type (made by a newer version?)".into());
        }
        (kb[0], sig_len, fp)
    } else if &magic == MAGIC3 {
        (KIND_FILE, 0usize, None)
    } else {
        return Err("not a pqe file".into());
    };

    let mut lb = [0u8; 2];
    r.read_exact(&mut lb)?;
    raw.extend_from_slice(&lb);
    let blob_len = u16::from_be_bytes(lb) as usize;
    if blob_len < 33 {
        return Err("corrupt file header".into());
    }
    let mut blob = vec![0u8; blob_len];
    r.read_exact(&mut blob)?;
    raw.extend_from_slice(&blob);
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    raw.extend_from_slice(&nonce);

    Ok(Header { raw, kind, sig_len, signer_fp, blob, nonce })
}

/// Mix both shared secrets (plus the X25519 public values) into one file key.
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

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

fn encrypt_stream(
    data: &Path,
    partial: &Path,
    ek: &Ek,
    rcpt_x_pk: &PublicKey,
    kind: u8,
    signer: Option<&SignId>,
) -> Res<()> {
    let mut rng = rand::thread_rng();
    let (kem_ct, ss_m) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "encapsulation failed")?;
    let eph = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pk = PublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(rcpt_x_pk);
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
    header.extend_from_slice(MAGIC4);
    header.push(kind);
    match signer {
        Some(s) => {
            header.extend_from_slice(&(SIG_LEN as u16).to_be_bytes());
            header.extend_from_slice(&Sha256::digest(&s.vk));
        }
        None => header.extend_from_slice(&0u16.to_be_bytes()),
    }
    header.extend_from_slice(&(blob_len as u16).to_be_bytes());
    header.extend_from_slice(eph_pk.as_bytes());
    header.extend_from_slice(kem_ct.as_slice());
    header.extend_from_slice(&nonce);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad key")?;
    let mut stream = Some(EncryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&nonce),
    ));

    let mut reader = BufReader::new(File::open(data)?);
    let mut writer = BufWriter::new(File::create(partial)?);
    writer.write_all(&header)?;

    let mut hasher = Sha512::new();
    hasher.update(SIG_LABEL);
    hasher.update(&header);

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
            hasher.update(&ct);
            writer.write_all(&ct)?;
            break;
        } else {
            let ct = stream
                .as_mut()
                .unwrap()
                .encrypt_next(payload)
                .map_err(|_| "encryption failed")?;
            hasher.update(&ct);
            writer.write_all(&ct)?;
        }
    }

    if let Some(s) = signer {
        let digest = hasher.finalize();
        let ed_sig: EdSignature = s.ed.sign(digest.as_slice());
        let ml_sig: MlSignature<MlDsa65> = s.ml.sign(digest.as_slice());
        let ml_bytes = ml_sig.encode();
        if ml_bytes.as_slice().len() != ML_SIG_LEN {
            return Err("unexpected signature size".into());
        }
        writer.write_all(&ed_sig.to_bytes())?;
        writer.write_all(ml_bytes.as_slice())?;
    }
    writer.flush()?;
    Ok(())
}

/// Encrypt a file or a whole folder to `<input>.pqe`. Optionally sign it.
pub fn encrypt(input: &str, pubkey: &str, sign: Option<SignOpts>) -> Res<String> {
    let src = Path::new(input.trim_end_matches(['/', '\\']));
    if !src.exists() {
        return Err(format!("not found: {}", src.display()).into());
    }
    let is_dir = src.is_dir();
    let out = PathBuf::from(format!("{}.{EXT}", src.display()));
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

    let signer = match &sign {
        Some(s) => {
            let seed = load_seed(&s.key_path, s.password.as_deref())?;
            Some(derive_signing(&seed)?)
        }
        None => None,
    };

    // Folders are packed into a temporary tar file first.
    let mut tar_tmp: Option<PathBuf> = None;
    let data_path: PathBuf = if is_dir {
        let t = PathBuf::from(format!("{}.tar-tmp", src.display()));
        let f = File::create(&t)?;
        let mut b = tar::Builder::new(BufWriter::new(f));
        b.follow_symlinks(false);
        let packed: Res<()> = (|| {
            b.append_dir_all(".", src)?;
            b.into_inner()?.flush()?;
            Ok(())
        })();
        if let Err(e) = packed {
            let _ = fs::remove_file(&t);
            return Err(e);
        }
        tar_tmp = Some(t.clone());
        t
    } else {
        src.to_path_buf()
    };

    let partial = PathBuf::from(format!("{}.partial", out.display()));
    let kind = if is_dir { KIND_DIR } else { KIND_FILE };
    let result = encrypt_stream(&data_path, &partial, &ek, &rcpt_x_pk, kind, signer.as_ref());
    if let Some(t) = &tar_tmp {
        let _ = fs::remove_file(t);
    }
    match result {
        Ok(()) => {
            fs::rename(&partial, &out)?;
            let signed = match &signer {
                Some(s) => format!("\nSigned (fingerprint {})", fmt_fp(&Sha256::digest(&s.vk))),
                None => String::new(),
            };
            Ok(format!("Encrypted -> {}{}", out.display(), signed))
        }
        Err(e) => {
            let _ = fs::remove_file(&partial);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypts into `partial` and checks the signature. Returns a one-line signature status.
fn decrypt_stream(
    reader: &mut BufReader<File>,
    h: &Header,
    cipher_len: u64,
    key: &[u8; 32],
    partial: &Path,
    verify_vk: Option<&str>,
) -> Res<String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "bad key")?;
    let mut stream = Some(DecryptorBE32::from_aead(
        cipher,
        GenericArray::from_slice(&h.nonce),
    ));
    let mut writer = BufWriter::new(File::create(partial)?);

    let mut hasher = Sha512::new();
    hasher.update(SIG_LABEL);
    hasher.update(&h.raw);

    let fail = "decryption failed: wrong key, or the file is corrupted/tampered with";
    let mut buf = vec![0u8; CHUNK + TAG];
    {
        let mut limited = reader.by_ref().take(cipher_len);
        loop {
            let n = read_full(&mut limited, &mut buf)?;
            hasher.update(&buf[..n]);
            let payload = Payload { msg: &buf[..n], aad: &h.raw };
            if n < CHUNK + TAG {
                let pt = stream
                    .take()
                    .unwrap()
                    .decrypt_last(payload)
                    .map_err(|_| fail)?;
                writer.write_all(&pt)?;
                break;
            } else {
                let pt = stream
                    .as_mut()
                    .unwrap()
                    .decrypt_next(payload)
                    .map_err(|_| fail)?;
                writer.write_all(&pt)?;
            }
        }
    }
    writer.flush()?;

    if h.sig_len == 0 {
        return Ok("Not signed (anyone who has your public key could have made this file).".to_string());
    }
    let mut sig = vec![0u8; h.sig_len];
    reader.read_exact(&mut sig)?;
    let digest = hasher.finalize();
    let fp = h.signer_fp.ok_or("corrupt file header")?;
    match verify_vk {
        Some(vkpath) => {
            let vk = fs::read(vkpath)?;
            if Sha256::digest(&vk).as_slice() != &fp[..] {
                return Err("this file was signed by a different key than the one you provided".into());
            }
            verify_sig(&vk, digest.as_slice(), &sig)?;
            Ok(format!("Signature VALID. Signed by fingerprint {}", fmt_fp(&fp)))
        }
        None => Ok(format!(
            "Warning: signed by fingerprint {}, but NOT verified (no sender key given). Check that fingerprint with the sender.",
            fmt_fp(&fp)
        )),
    }
}

/// Decrypt a `.pqe` file or folder. Pass the sender's `.vk` to require a valid signature.
pub fn decrypt(
    input: &str,
    privkey: &str,
    password: Option<&str>,
    verify_vk: Option<&str>,
) -> Res<String> {
    let src = Path::new(input);
    let file_len = fs::metadata(src)?.len();
    let mut reader = BufReader::new(File::open(src)?);
    let h = read_header(&mut reader)?;

    let header_len = h.raw.len() as u64;
    let trailer = h.sig_len as u64;
    if file_len < header_len + trailer {
        return Err("file is truncated".into());
    }
    let cipher_len = file_len - header_len - trailer;

    if verify_vk.is_some() && h.sig_len == 0 {
        return Err("this file is not signed, but you asked to verify a sender. Refusing to open it.".into());
    }

    let seed = load_seed(privkey, password)?;
    let keys = expand_seed(&seed)?;
    let mut eb = [0u8; 32];
    eb.copy_from_slice(&h.blob[..32]);
    let eph_pk = PublicKey::from(eb);
    let ss_x = keys.x_sk.diffie_hellman(&eph_pk);
    if !ss_x.was_contributory() {
        return Err("corrupt file header".into());
    }
    let ct = Ciphertext::<Kem>::try_from(&h.blob[32..]).map_err(|_| "corrupt file header")?;
    let ss_m = keys.dk.decapsulate(&ct).map_err(|_| "decapsulation failed")?;
    let key = file_key(
        ss_m.as_slice(),
        ss_x.as_bytes(),
        eph_pk.as_bytes(),
        keys.x_pk.as_bytes(),
    )?;

    let base = if src.extension().and_then(|e| e.to_str()) == Some(EXT) {
        src.with_extension("")
    } else {
        PathBuf::from(format!("{input}.dec"))
    };
    let out = unique_path(base);
    let partial = PathBuf::from(format!("{}.partial", out.display()));

    let status = match decrypt_stream(&mut reader, &h, cipher_len, &key, &partial, verify_vk) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(&partial);
            return Err(e);
        }
    };

    if h.kind == KIND_DIR {
        let unpacked: Res<()> = (|| {
            let f = File::open(&partial)?;
            fs::create_dir_all(&out)?;
            let mut ar = tar::Archive::new(BufReader::new(f));
            ar.unpack(&out)?;
            Ok(())
        })();
        let _ = fs::remove_file(&partial);
        if let Err(e) = unpacked {
            let _ = fs::remove_dir_all(&out);
            return Err(e);
        }
    } else {
        fs::rename(&partial, &out)?;
    }
    Ok(format!("Decrypted -> {}\n{}", out.display(), status))
}

// ---------------------------------------------------------------------------
// Tests: run with `cargo test --release --no-default-features`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn p(dir: &Path, name: &str) -> String {
        dir.join(name).to_string_lossy().to_string()
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn roundtrip_len(len: usize) {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let f = p(d.path(), "data.bin");
        let data = sample(len);
        fs::write(&f, &data).unwrap();
        encrypt(&f, &format!("{k}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        decrypt(&format!("{f}.pqe"), &format!("{k}.key"), None, None).unwrap();
        assert_eq!(fs::read(&f).unwrap(), data);
    }

    #[test]
    fn roundtrip_small() {
        roundtrip_len(13);
    }

    #[test]
    fn roundtrip_empty() {
        roundtrip_len(0);
    }

    #[test]
    fn roundtrip_exact_chunk() {
        roundtrip_len(CHUNK);
    }

    #[test]
    fn roundtrip_two_exact_chunks() {
        roundtrip_len(2 * CHUNK);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        roundtrip_len(2 * CHUNK + 12345);
    }

    #[test]
    fn key_sizes_are_as_documented() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        assert_eq!(fs::read(format!("{k}.pub")).unwrap().len(), 1216);
        assert_eq!(fs::read(format!("{k}.vk")).unwrap().len(), VK_LEN);
        assert_eq!(fs::read(format!("{k}.key")).unwrap().len(), 32);
    }

    #[test]
    fn wrong_key_fails_and_leaves_no_output() {
        let d = tempdir().unwrap();
        let (a, b) = (p(d.path(), "a"), p(d.path(), "b"));
        keygen(&a, None).unwrap();
        keygen(&b, None).unwrap();
        let f = p(d.path(), "x.txt");
        fs::write(&f, b"secret").unwrap();
        encrypt(&f, &format!("{a}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        assert!(decrypt(&format!("{f}.pqe"), &format!("{b}.key"), None, None).is_err());
        assert!(!Path::new(&f).exists());
        assert!(!Path::new(&format!("{f}.partial")).exists());
    }

    #[test]
    fn tampering_is_detected() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let f = p(d.path(), "x.bin");
        fs::write(&f, sample(CHUNK + 500)).unwrap();
        encrypt(&f, &format!("{k}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        let enc = format!("{f}.pqe");
        let mut bytes = fs::read(&enc).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        fs::write(&enc, &bytes).unwrap();
        assert!(decrypt(&enc, &format!("{k}.key"), None, None).is_err());
        assert!(!Path::new(&f).exists());
    }

    #[test]
    fn truncation_is_detected() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let f = p(d.path(), "x.bin");
        fs::write(&f, sample(2 * CHUNK + 7)).unwrap();
        encrypt(&f, &format!("{k}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        let enc = format!("{f}.pqe");
        let bytes = fs::read(&enc).unwrap();
        fs::write(&enc, &bytes[..bytes.len() - 5]).unwrap();
        assert!(decrypt(&enc, &format!("{k}.key"), None, None).is_err());
        assert!(!Path::new(&f).exists());
    }

    #[test]
    fn decrypt_never_overwrites() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let f = p(d.path(), "x.txt");
        fs::write(&f, b"original").unwrap();
        encrypt(&f, &format!("{k}.pub"), None).unwrap();
        let msg = decrypt(&format!("{f}.pqe"), &format!("{k}.key"), None, None).unwrap();
        assert!(msg.contains("(2)"));
        assert_eq!(fs::read(&f).unwrap(), b"original");
    }

    #[test]
    fn password_protected_key() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, Some("correct horse")).unwrap();
        let key = format!("{k}.key");
        assert!(key_is_protected(&key));
        assert_eq!(fs::read(&key).unwrap().len(), 92);
        let f = p(d.path(), "x.txt");
        fs::write(&f, b"hello").unwrap();
        encrypt(&f, &format!("{k}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        let enc = format!("{f}.pqe");
        assert!(decrypt(&enc, &key, None, None).is_err());
        assert!(decrypt(&enc, &key, Some("wrong"), None).is_err());
        decrypt(&enc, &key, Some("correct horse"), None).unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"hello");
    }

    #[test]
    fn empty_password_is_rejected() {
        let d = tempdir().unwrap();
        assert!(keygen(&p(d.path(), "k"), Some("")).is_err());
    }

    #[test]
    fn signatures_work() {
        let d = tempdir().unwrap();
        let (alice, bob, eve) = (p(d.path(), "alice"), p(d.path(), "bob"), p(d.path(), "eve"));
        keygen(&alice, None).unwrap();
        keygen(&bob, None).unwrap();
        keygen(&eve, None).unwrap();
        let f = p(d.path(), "m.txt");
        fs::write(&f, b"hello").unwrap();
        let sign = SignOpts { key_path: format!("{alice}.key"), password: None };
        encrypt(&f, &format!("{bob}.pub"), Some(sign)).unwrap();
        let enc = format!("{f}.pqe");
        let bob_key = format!("{bob}.key");
        let alice_vk = format!("{alice}.vk");
        let eve_vk = format!("{eve}.vk");

        // Right sender key: valid.
        let msg = decrypt(&enc, &bob_key, None, Some(alice_vk.as_str())).unwrap();
        assert!(msg.contains("Signature VALID"));
        fs::remove_file(&f).unwrap();

        // Wrong sender key: refused, nothing left behind.
        assert!(decrypt(&enc, &bob_key, None, Some(eve_vk.as_str())).is_err());
        assert!(!Path::new(&f).exists());

        // No sender key: opens, but warns that it was not verified.
        let msg = decrypt(&enc, &bob_key, None, None).unwrap();
        assert!(msg.contains("NOT verified"));
    }

    #[test]
    fn tampered_signed_file_is_rejected() {
        let d = tempdir().unwrap();
        let (alice, bob) = (p(d.path(), "alice"), p(d.path(), "bob"));
        keygen(&alice, None).unwrap();
        keygen(&bob, None).unwrap();
        let f = p(d.path(), "m.txt");
        fs::write(&f, b"hello").unwrap();
        let sign = SignOpts { key_path: format!("{alice}.key"), password: None };
        encrypt(&f, &format!("{bob}.pub"), Some(sign)).unwrap();
        fs::remove_file(&f).unwrap();
        let enc = format!("{f}.pqe");
        let mut bytes = fs::read(&enc).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // flip a bit inside the ML-DSA signature
        fs::write(&enc, &bytes).unwrap();
        let alice_vk = format!("{alice}.vk");
        let r = decrypt(&enc, &format!("{bob}.key"), None, Some(alice_vk.as_str()));
        assert!(r.is_err());
        assert!(!Path::new(&f).exists());
    }

    #[test]
    fn requiring_a_signature_on_an_unsigned_file_fails() {
        let d = tempdir().unwrap();
        let (alice, bob) = (p(d.path(), "alice"), p(d.path(), "bob"));
        keygen(&alice, None).unwrap();
        keygen(&bob, None).unwrap();
        let f = p(d.path(), "m.txt");
        fs::write(&f, b"hello").unwrap();
        encrypt(&f, &format!("{bob}.pub"), None).unwrap();
        fs::remove_file(&f).unwrap();
        let alice_vk = format!("{alice}.vk");
        let r = decrypt(&format!("{f}.pqe"), &format!("{bob}.key"), None, Some(alice_vk.as_str()));
        assert!(r.is_err());
        assert!(!Path::new(&f).exists());
    }

    #[test]
    fn export_vk_matches_keygen() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let original = fs::read(format!("{k}.vk")).unwrap();
        fs::remove_file(format!("{k}.vk")).unwrap();
        export_vk(&format!("{k}.key"), None).unwrap();
        assert_eq!(fs::read(format!("{k}.vk")).unwrap(), original);
    }

    #[test]
    fn folder_roundtrip() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let dir = d.path().join("stuff");
        fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        fs::write(dir.join("a.txt"), b"alpha").unwrap();
        fs::write(dir.join("sub/b.bin"), sample(CHUNK + CHUNK / 2)).unwrap();
        fs::write(dir.join("sub/deeper/c.txt"), b"gamma").unwrap();
        let ds = dir.to_string_lossy().to_string();
        encrypt(&ds, &format!("{k}.pub"), None).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        decrypt(&format!("{ds}.pqe"), &format!("{k}.key"), None, None).unwrap();
        assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dir.join("sub/b.bin")).unwrap(), sample(CHUNK + CHUNK / 2));
        assert_eq!(fs::read(dir.join("sub/deeper/c.txt")).unwrap(), b"gamma");
    }

    #[test]
    fn fingerprint_format() {
        let d = tempdir().unwrap();
        let k = p(d.path(), "k");
        keygen(&k, None).unwrap();
        let fp = fingerprint(&format!("{k}.pub")).unwrap();
        assert_eq!(fp.len(), 39); // 8 groups of 4 hex chars + 7 spaces
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
}