use crate::crypto::backend::{AeadProvider, CryptoBackend, CryptoLevel, HeaderProtectionProvider, KeySchedule, TlsSession};
use crate::error::{CryptoError, Error, Result};
use crate::types::{ConnectionId, PacketNumber, Side};
use boring_sys as ffi;
use std::ptr;
use std::ffi::c_int;

pub struct BoringCryptoBackend;

impl CryptoBackend for BoringCryptoBackend {
    fn create_aead(&self, cipher_suite: u16) -> Result<Box<dyn AeadProvider>> {
        unsafe {
            let aead = match cipher_suite {
                0x1301 => ffi::EVP_aead_aes_128_gcm(),
                0x1302 => ffi::EVP_aead_aes_256_gcm(),
                0x1303 => ffi::EVP_aead_chacha20_poly1305(),
                _ => return Err(Error::Crypto(CryptoError { code: 0x0150 })),
            };
            Ok(Box::new(BoringAead::new(aead)))
        }
    }

    fn create_header_protection(&self, cipher_suite: u16) -> Result<Box<dyn HeaderProtectionProvider>> {
        unsafe {
            let (cipher, is_chacha) = match cipher_suite {
                0x1301 => (ffi::EVP_aes_128_ecb(), false),
                0x1302 => (ffi::EVP_aes_256_ecb(), false),
                0x1303 => (
                    ffi::EVP_get_cipherbyname(b"chacha20\0".as_ptr() as *const i8),
                    true
                ),
                _ => return Err(Error::Crypto(CryptoError { code: 0x0150 })),
            };
            if cipher.is_null() {
                 return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
            Ok(Box::new(BoringHeaderProtection { cipher, is_chacha }))
        }
    }

    fn create_key_schedule(&self) -> Box<dyn KeySchedule> {
        Box::new(BoringKeySchedule)
    }

    fn create_tls_session(
        &self,
        side: Side,
        server_name: Option<&str>,
        alpn_protocols: &[&[u8]],
        cert_data: Option<&[u8]>,
        key_data: Option<&[u8]>,
    ) -> Result<Box<dyn TlsSession>> {
        match side {
            Side::Client => crate::tls::boringssl::BoringTlsSession::new_client(server_name, alpn_protocols),
            Side::Server => crate::tls::boringssl::BoringTlsSession::new_server(alpn_protocols, cert_data, key_data),
        }
    }
}

struct BoringAead {
    aead: *const ffi::EVP_AEAD,
}

unsafe impl Send for BoringAead {}
unsafe impl Sync for BoringAead {}

impl BoringAead {
    fn new(aead: *const ffi::EVP_AEAD) -> Self {
        Self { aead }
    }
}

impl AeadProvider for BoringAead {
    fn key_len(&self) -> usize {
        unsafe { ffi::EVP_AEAD_key_length(self.aead) }
    }

    fn iv_len(&self) -> usize {
        unsafe { ffi::EVP_AEAD_nonce_length(self.aead) }
    }

    fn seal(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        unsafe {
            // RFC 9001 Section 5.3: Construct nonce by XORing IV with left-padded packet number
            let iv_len = iv.len();
            let mut nonce = vec![0u8; iv_len];
            nonce.copy_from_slice(iv);
            
            // Packet number in network byte order (big-endian), left-padded with zeros
            let pn_bytes = packet_number.to_be_bytes();
            // XOR the last bytes of nonce with packet number bytes
            // Nonce is typically 12 bytes, packet number is 8 bytes max
            let pn_start = iv_len.saturating_sub(8);
            for i in 0..8.min(iv_len - pn_start) {
                nonce[pn_start + i] ^= pn_bytes[i];
            }
            
            let mut ctx: ffi::EVP_AEAD_CTX = std::mem::zeroed();
            if ffi::EVP_AEAD_CTX_init(
                &mut ctx,
                self.aead,
                key.as_ptr(),
                key.len(),
                ffi::EVP_AEAD_DEFAULT_TAG_LENGTH as usize,
                ptr::null_mut(),
            ) != 1 {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }

            struct AeadCtx(ffi::EVP_AEAD_CTX);
            impl Drop for AeadCtx {
                fn drop(&mut self) {
                    unsafe { ffi::EVP_AEAD_CTX_cleanup(&mut self.0) };
                }
            }
            let mut ctx_guard = AeadCtx(ctx);

            let mut out_len = 0;
            if ffi::EVP_AEAD_CTX_seal(
                &mut ctx_guard.0,
                output.as_mut_ptr(),
                &mut out_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.as_ptr(),
                payload.len(),
                header.as_ptr(),
                header.len(),
            ) != 1 {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
            Ok(out_len)
        }
    }

    fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        unsafe {
            // RFC 9001 Section 5.3: Construct nonce by XORing IV with left-padded packet number
            let iv_len = iv.len();
            let mut nonce = vec![0u8; iv_len];
            nonce.copy_from_slice(iv);
            
            // Packet number in network byte order (big-endian), left-padded with zeros
            // RFC 9001 Section 5.3: "The 62 bits of the reconstructed QUIC packet number
            // in network byte order are left-padded with zeros to the size of the IV.
            // The exclusive OR of the padded packet number and the IV forms the AEAD nonce."
            let pn_bytes = packet_number.to_be_bytes();
            // XOR the last bytes of nonce with packet number bytes
            // For a 12-byte IV, we XOR the last 8 bytes (or fewer if IV is shorter)
            // This effectively left-pads the packet number with zeros
            let bytes_to_xor = 8.min(iv_len);
            let start_idx = iv_len - bytes_to_xor;
            for i in 0..bytes_to_xor {
                nonce[start_idx + i] ^= pn_bytes[i];
            }
            
            let mut ctx: ffi::EVP_AEAD_CTX = std::mem::zeroed();
            if ffi::EVP_AEAD_CTX_init(
                &mut ctx,
                self.aead,
                key.as_ptr(),
                key.len(),
                ffi::EVP_AEAD_DEFAULT_TAG_LENGTH as usize,
                ptr::null_mut(),
            ) != 1 {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }

            struct AeadCtx(ffi::EVP_AEAD_CTX);
            impl Drop for AeadCtx {
                fn drop(&mut self) {
                    unsafe { ffi::EVP_AEAD_CTX_cleanup(&mut self.0) };
                }
            }
            let mut ctx_guard = AeadCtx(ctx);

            let mut out_len = 0;
            if ffi::EVP_AEAD_CTX_open(
                &mut ctx_guard.0,
                output.as_mut_ptr(),
                &mut out_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.as_ptr(),
                payload.len(),
                header.as_ptr(),
                header.len(),
            ) != 1 {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
            Ok(out_len)
        }
    }

    fn tag_len(&self) -> usize {
        unsafe { ffi::EVP_AEAD_max_tag_len(self.aead) }
    }
}

struct BoringHeaderProtection {
    cipher: *const ffi::EVP_CIPHER,
    is_chacha: bool,
}

unsafe impl Send for BoringHeaderProtection {}
unsafe impl Sync for BoringHeaderProtection {}

impl HeaderProtectionProvider for BoringHeaderProtection {
    fn key_len(&self) -> usize {
        unsafe { ffi::EVP_CIPHER_key_length(self.cipher) as usize }
    }

    fn sample_len(&self) -> usize {
        16
    }

    fn build_mask(&self, key: &[u8], sample: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            let ctx = ffi::EVP_CIPHER_CTX_new();
            if ctx.is_null() {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
            
            struct CipherCtx(*mut ffi::EVP_CIPHER_CTX);
            impl Drop for CipherCtx {
                fn drop(&mut self) {
                    unsafe { ffi::EVP_CIPHER_CTX_free(self.0) };
                }
            }
            let _ctx_guard = CipherCtx(ctx);

            let mut mask = [0u8; 5];
            let mut out_len = 0;

            if self.is_chacha {
                 let zeros = [0u8; 5];
                 if ffi::EVP_EncryptInit_ex(ctx, self.cipher, ptr::null_mut(), key.as_ptr(), sample.as_ptr()) != 1 {
                     return Err(Error::Crypto(CryptoError { code: 0x0150 }));
                 }
                 if ffi::EVP_EncryptUpdate(ctx, mask.as_mut_ptr(), &mut out_len, zeros.as_ptr(), zeros.len() as i32) != 1 {
                     return Err(Error::Crypto(CryptoError { code: 0x0150 }));
                 }
            } else {
                 if ffi::EVP_EncryptInit_ex(ctx, self.cipher, ptr::null_mut(), key.as_ptr(), ptr::null_mut()) != 1 {
                     return Err(Error::Crypto(CryptoError { code: 0x0150 }));
                 }
                 let mut out = [0u8; 32];
                 if ffi::EVP_EncryptUpdate(ctx, out.as_mut_ptr(), &mut out_len, sample.as_ptr(), sample.len() as i32) != 1 {
                     return Err(Error::Crypto(CryptoError { code: 0x0150 }));
                 }
                 mask.copy_from_slice(&out[0..5]);
            }
            
            if output.len() >= 5 {
                output[0..5].copy_from_slice(&mask);
            }
            Ok(())
        }
    }
}

// Helper functions for HKDF
// BoringSSL HKDF_extract signature: (out, out_len, md, secret, secret_len, salt, salt_len)
// where secret is the IKM (Input Keying Material) and salt is the salt
// RFC 9001: HKDF-Extract(salt, IKM) -> PRK
// So we call: HKDF_extract(..., IKM, salt)
fn hkdf_extract(ikm: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        hkdf_extract_with_hash(ikm, salt, ffi::EVP_sha256())
    }
}

fn hkdf_extract_with_hash(ikm: &[u8], salt: &[u8], md: *const ffi::EVP_MD) -> Result<Vec<u8>> {
    unsafe {
        let mut out_len: usize = 0;
        let mut out = vec![0u8; ffi::EVP_MAX_MD_SIZE as usize];
        if ffi::HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            md,
            ikm.as_ptr(),      // IKM (Input Keying Material)
            ikm.len(),
            salt.as_ptr(),     // Salt
            salt.len(),
        ) != 1 {
             return Err(Error::Crypto(CryptoError { code: 0x0150 }));
        }
        out.truncate(out_len);
        Ok(out)
    }
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    unsafe {
        hkdf_expand_with_hash(prk, info, len, ffi::EVP_sha256())
    }
}

fn hkdf_expand_with_hash(prk: &[u8], info: &[u8], len: usize, md: *const ffi::EVP_MD) -> Result<Vec<u8>> {
    unsafe {
        let mut out = vec![0u8; len];
        if ffi::HKDF_expand(
            out.as_mut_ptr(),
            len,
            md,
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
        ) != 1 {
             return Err(Error::Crypto(CryptoError { code: 0x0150 }));
        }
        Ok(out)
    }
}

fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
    unsafe {
        hkdf_expand_label_with_hash(secret, label, context, len, ffi::EVP_sha256())
    }
}

fn hkdf_expand_label_with_hash(secret: &[u8], label: &str, context: &[u8], len: usize, md: *const ffi::EVP_MD) -> Result<Vec<u8>> {
    // RFC 8446 Section 7.1: HKDF-Expand-Label structure
    // Info = OutputLength (2 bytes) || LabelLength (1 byte) || Label (variable) || ContextLength (1 byte) || Context (variable)
    // Label = "tls13 " || label
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let label_bytes = label.as_bytes();
    
    let mut info = Vec::new();
    // OutputLength (2 bytes, big-endian u16)
    info.extend_from_slice(&(len as u16).to_be_bytes());
    // LabelLength (1 byte): length of LABEL_PREFIX + label
    info.push((LABEL_PREFIX.len() + label_bytes.len()) as u8);
    // Label: LABEL_PREFIX || label
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label_bytes);
    // ContextLength (1 byte)
    info.push(context.len() as u8);
    // Context
    info.extend_from_slice(context);
    
    hkdf_expand_with_hash(secret, &info, len, md)
}

struct BoringKeySchedule;

impl KeySchedule for BoringKeySchedule {
    fn derive_initial_secret(&self, dcid: &ConnectionId, _version: u32) -> Result<[u8; 32]> {
        let initial_salt = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
        ];
        // RFC 9001 Section 5.2: initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
        // In BoringSSL HKDF_extract: (out, md, secret, salt) where secret is IKM and salt is salt
        // So we pass: secret=dcid (IKM), salt=initial_salt
        let secret = hkdf_extract(dcid.as_bytes(), &initial_salt)?;
        let mut out = [0u8; 32];
        if secret.len() != 32 {
             return Err(Error::Crypto(CryptoError { code: 0x0150 }));
        }
        out.copy_from_slice(&secret);
        Ok(out)
    }

    fn derive_client_initial_secret(&self, initial_secret: &[u8]) -> Result<[u8; 32]> {
        let secret = hkdf_expand_label(initial_secret, "client in", &[], 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&secret);
        Ok(out)
    }

    fn derive_server_initial_secret(&self, initial_secret: &[u8]) -> Result<[u8; 32]> {
        let secret = hkdf_expand_label(initial_secret, "server in", &[], 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&secret);
        Ok(out)
    }

    fn derive_packet_key(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>> {
        // RFC 9001 Section 5.1: Hash function matches cipher suite
        // 0x1301 (AES_128_GCM_SHA256) and 0x1303 (CHACHA20_POLY1305_SHA256) use SHA-256
        // 0x1302 (AES_256_GCM_SHA384) uses SHA-384
        let md = unsafe {
            match cipher_suite {
                0x1302 => ffi::EVP_sha384(),
                _ => ffi::EVP_sha256(),
            }
        };
        hkdf_expand_label_with_hash(secret, "quic key", &[], len, md)
    }

    fn derive_packet_iv(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>> {
        let md = unsafe {
            match cipher_suite {
                0x1302 => ffi::EVP_sha384(),
                _ => ffi::EVP_sha256(),
            }
        };
        hkdf_expand_label_with_hash(secret, "quic iv", &[], len, md)
    }

    fn derive_header_protection_key(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>> {
        let md = unsafe {
            match cipher_suite {
                0x1302 => ffi::EVP_sha384(),
                _ => ffi::EVP_sha256(),
            }
        };
        hkdf_expand_label_with_hash(secret, "quic hp", &[], len, md)
    }
}
