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
    ) -> Result<Box<dyn TlsSession>> {
        match side {
            Side::Client => crate::tls::boringssl::BoringTlsSession::new_client(server_name, alpn_protocols),
            Side::Server => crate::tls::boringssl::BoringTlsSession::new_server(alpn_protocols),
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
        _packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        unsafe {
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
                iv.as_ptr(),
                iv.len(),
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
        _packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        unsafe {
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
                iv.as_ptr(),
                iv.len(),
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
fn hkdf_extract(salt: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut out_len: usize = 0;
        let mut out = vec![0u8; ffi::EVP_MAX_MD_SIZE as usize];
        if ffi::HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            ffi::EVP_sha256(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
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
        let mut out = vec![0u8; len];
        if ffi::HKDF_expand(
            out.as_mut_ptr(),
            len,
            ffi::EVP_sha256(),
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
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full_label = format!("tls13 {}", label);
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

struct BoringKeySchedule;

impl KeySchedule for BoringKeySchedule {
    fn derive_initial_secret(&self, dcid: &ConnectionId, _version: u32) -> Result<[u8; 32]> {
        let initial_salt = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
        ];
        let secret = hkdf_extract(&initial_salt, dcid.as_bytes())?;
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

    fn derive_packet_key(&self, secret: &[u8], len: usize) -> Result<Vec<u8>> {
        hkdf_expand_label(secret, "quic key", &[], len)
    }

    fn derive_packet_iv(&self, secret: &[u8], len: usize) -> Result<Vec<u8>> {
        hkdf_expand_label(secret, "quic iv", &[], len)
    }

    fn derive_header_protection_key(&self, secret: &[u8], len: usize) -> Result<Vec<u8>> {
        hkdf_expand_label(secret, "quic hp", &[], len)
    }
}
