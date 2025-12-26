use crate::crypto::backend::{CryptoLevel, TlsEvent, TlsSession};
use crate::error::{CryptoError, Error, Result};
use boring::ssl::{Ssl, SslContext, SslMethod, SslVersion};
use boring_sys as ffi;
use std::ffi::c_void;
use std::ptr;
use std::collections::VecDeque;
use foreign_types::ForeignType;

static mut EX_DATA_INDEX: i32 = -1;
static EX_DATA_INDEX_INIT: std::sync::Once = std::sync::Once::new();

fn get_ex_data_index() -> i32 {
    unsafe {
        EX_DATA_INDEX_INIT.call_once(|| {
            EX_DATA_INDEX = ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None);
        });
        EX_DATA_INDEX
    }
}

struct ExData<'a> {
    events: &'a mut VecDeque<TlsEvent>,
}

pub struct BoringTlsSession {
    ssl: Ssl,
    events: VecDeque<TlsEvent>,
    is_server: bool,
}

impl BoringTlsSession {
    pub fn new_client(server_name: Option<&str>, alpn_protocols: &[&[u8]]) -> Result<Box<dyn TlsSession>> {
        let mut ctx = SslContext::builder(SslMethod::tls_client())
            .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;
        
        ctx.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;
        
        ctx.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;

        // Set ALPN
        if !alpn_protocols.is_empty() {
            let mut protos = Vec::new();
            for proto in alpn_protocols {
                protos.push(proto.len() as u8);
                protos.extend_from_slice(proto);
            }
            ctx.set_alpn_protos(&protos)
                .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;
        }

        let ctx = ctx.build();
        let mut ssl = Ssl::new(&ctx)
            .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;

        if let Some(name) = server_name {
            ssl.set_hostname(name)
                .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;
        }

        unsafe {
            ffi::SSL_set_connect_state(ssl.as_ptr());
            ffi::SSL_set_quic_method(ssl.as_ptr(), &QUIC_METHOD);
        }

        Ok(Box::new(Self {
            ssl,
            events: VecDeque::new(),
            is_server: false,
        }))
    }

    pub fn new_server(
        alpn_protocols: &[&[u8]],
        cert_data: Option<&[u8]>,
        key_data: Option<&[u8]>,
    ) -> Result<Box<dyn TlsSession>> {
        eprintln!("DEBUG: BoringTlsSession::new_server called: cert_data={:?}, key_data={:?}, alpn_protocols={:?}", 
                 cert_data.map(|d| d.len()), key_data.map(|d| d.len()), alpn_protocols);
        
        let mut ctx = SslContext::builder(SslMethod::tls_server())
            .map_err(|e| {
                eprintln!("DEBUG: Failed to create SSL context builder: {:?}", e);
                Error::Crypto(CryptoError { code: 0x0150 })
            })?;
        
        ctx.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| {
                eprintln!("DEBUG: Failed to set min proto version: {:?}", e);
                Error::Crypto(CryptoError { code: 0x0150 })
            })?;
        
        ctx.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| {
                eprintln!("DEBUG: Failed to set max proto version: {:?}", e);
                Error::Crypto(CryptoError { code: 0x0150 })
            })?;

        // Load certificate and private key from memory
        match (cert_data, key_data) {
            (Some(cert_bytes), Some(key_bytes)) => {
                eprintln!("DEBUG: Loading certificate ({} bytes) and key ({} bytes)", cert_bytes.len(), key_bytes.len());
                
                // Parse certificate chain from PEM
                use boring::x509::X509;
                let cert = X509::from_pem(cert_bytes)
                    .map_err(|e| {
                        eprintln!("DEBUG: Failed to parse certificate PEM: {:?}", e);
                        Error::Crypto(CryptoError { code: 0x0150 })
                    })?;
                
                eprintln!("DEBUG: Certificate parsed successfully");
                
                // Set certificate
                ctx.set_certificate(&cert)
                    .map_err(|e| {
                        eprintln!("DEBUG: Failed to set certificate: {:?}", e);
                        Error::Crypto(CryptoError { code: 0x0150 })
                    })?;
                
                eprintln!("DEBUG: Certificate set successfully");
                
                // Parse private key from PEM
                use boring::pkey::PKey;
                let key = PKey::private_key_from_pem(key_bytes)
                    .map_err(|e| {
                        eprintln!("DEBUG: Failed to parse private key PEM: {:?}", e);
                        Error::Crypto(CryptoError { code: 0x0150 })
                    })?;
                
                eprintln!("DEBUG: Private key parsed successfully");
                
                // Set private key
                ctx.set_private_key(&key)
                    .map_err(|e| {
                        eprintln!("DEBUG: Failed to set private key: {:?}", e);
                        Error::Crypto(CryptoError { code: 0x0150 })
                    })?;
                
                eprintln!("DEBUG: Private key set successfully");
            }
            (None, None) => {
                eprintln!("DEBUG: WARNING: No certificate or key data provided!");
            }
            _ => {
                eprintln!("DEBUG: ERROR: Certificate and key must both be provided or both be None");
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
        }

        // Set ALPN callback
        if !alpn_protocols.is_empty() {
            let mut protos_flat = Vec::new();
            for p in alpn_protocols {
                protos_flat.push(p.len() as u8);
                protos_flat.extend_from_slice(p);
            }
            
            ctx.set_alpn_select_callback(move |_, client_protos| {
                let mut client_idx = 0;
                while client_idx < client_protos.len() {
                    let len = client_protos[client_idx] as usize;
                    client_idx += 1;
                    if client_idx + len > client_protos.len() {
                        break;
                    }
                    let proto = &client_protos[client_idx..client_idx + len];
                    
                    let mut server_idx = 0;
                    while server_idx < protos_flat.len() {
                        let slen = protos_flat[server_idx] as usize;
                        server_idx += 1;
                        if server_idx + slen > protos_flat.len() {
                            break;
                        }
                        let sproto = &protos_flat[server_idx..server_idx + slen];
                        if proto == sproto {
                            return Ok(proto);
                        }
                        server_idx += slen;
                    }
                    
                    client_idx += len;
                }
                Err(boring::ssl::AlpnError::NOACK)
            });
        }

        let ctx = ctx.build();
        let ssl = Ssl::new(&ctx)
            .map_err(|_| Error::Crypto(CryptoError { code: 0x0150 }))?;

        unsafe {
            ffi::SSL_set_accept_state(ssl.as_ptr());
            ffi::SSL_set_quic_method(ssl.as_ptr(), &QUIC_METHOD);
        }

        Ok(Box::new(Self {
            ssl,
            events: VecDeque::new(),
            is_server: true,
        }))
    }
}

impl TlsSession for BoringTlsSession {
    fn process_input(&mut self, data: &[u8], level: CryptoLevel) -> Result<()> {
        let level_int = match level {
            CryptoLevel::Initial => ffi::ssl_encryption_level_t::ssl_encryption_initial,
            CryptoLevel::ZeroRTT => ffi::ssl_encryption_level_t::ssl_encryption_early_data,
            CryptoLevel::Handshake => ffi::ssl_encryption_level_t::ssl_encryption_handshake,
            CryptoLevel::OneRTT => ffi::ssl_encryption_level_t::ssl_encryption_application,
        };

        let mut ex_data = ExData {
            events: &mut self.events,
        };

        unsafe {
            ffi::SSL_set_ex_data(self.ssl.as_ptr(), get_ex_data_index(), &mut ex_data as *mut ExData as *mut c_void);

            let provide_result = ffi::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                level_int,
                data.as_ptr(),
                data.len(),
            );
            if provide_result != 1 {
                let ssl_error = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), provide_result) };
                let error_code = unsafe { ffi::ERR_get_error() };
                ffi::SSL_set_ex_data(self.ssl.as_ptr(), get_ex_data_index(), ptr::null_mut());
                eprintln!("DEBUG: SSL_provide_quic_data failed: result={}, ssl_error={:?}, error_code={:x}, level={:?}, data_len={}", 
                         provide_result, ssl_error, error_code, level, data.len());
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }

            let handshake_result = ffi::SSL_do_handshake(self.ssl.as_ptr());
            let err = ffi::SSL_get_error(self.ssl.as_ptr(), handshake_result);
            ffi::SSL_set_ex_data(self.ssl.as_ptr(), get_ex_data_index(), ptr::null_mut());
            
            // Check if handshake completed
            if handshake_result == 1 {
                // Handshake completed successfully
                if !self.events.iter().any(|e| matches!(e, TlsEvent::HandshakeComplete)) {
                    self.events.push_back(TlsEvent::HandshakeComplete);
                }
            } else {
                // Handshake not complete yet
                match err {
                    ffi::SSL_ERROR_WANT_READ | ffi::SSL_ERROR_WANT_WRITE => {
                        // Normal - need more data
                        return Ok(());
                    }
                    _ => {
                        // Error occurred
                        return Err(Error::Crypto(CryptoError { code: 0x0150 }));
                    }
                }
            }
        }
        
        Ok(())
    }

    fn get_output(&mut self) -> Option<TlsEvent> {
        self.events.pop_front()
    }

    fn is_handshake_complete(&self) -> bool {
        unsafe { ffi::SSL_in_init(self.ssl.as_ptr()) == 0 }
    }

    fn alpn_protocol(&self) -> Option<Vec<u8>> {
        if let Some(proto) = self.ssl.selected_alpn_protocol() {
            Some(proto.to_vec())
        } else {
            None
        }
    }

    fn peer_transport_params(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut ptr: *const u8 = ptr::null();
            let mut len: usize = 0;
            ffi::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                return None;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(slice.to_vec())
        }
    }

    fn set_transport_params(&mut self, params: &[u8]) -> Result<()> {
        unsafe {
            if ffi::SSL_set_quic_transport_params(
                self.ssl.as_ptr(),
                params.as_ptr(),
                params.len(),
            ) != 1 {
                return Err(Error::Crypto(CryptoError { code: 0x0150 }));
            }
        }
        Ok(())
    }
}

// QUIC Method Callbacks
static QUIC_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

unsafe extern "C" fn set_read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> i32 {
    let ex_data_ptr = ffi::SSL_get_ex_data(ssl, get_ex_data_index()) as *mut ExData;
    if ex_data_ptr.is_null() {
        return 0;
    }
    let ex_data = &mut *ex_data_ptr;

    let slice = std::slice::from_raw_parts(secret, secret_len);
    let vec = slice.to_vec();

    let crypto_level = match level {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => CryptoLevel::Initial,
        ffi::ssl_encryption_level_t::ssl_encryption_early_data => CryptoLevel::ZeroRTT,
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => CryptoLevel::Handshake,
        ffi::ssl_encryption_level_t::ssl_encryption_application => CryptoLevel::OneRTT,
        _ => return 0,
    };

    // Extract cipher suite ID from SSL_CIPHER
    // SSL_CIPHER_get_id returns the full cipher ID (0x03000000 | suite_id)
    // We need to mask to get just the suite ID (lower 16 bits)
    let cipher_suite = if !cipher.is_null() {
        let full_id = ffi::SSL_CIPHER_get_id(cipher);
        (full_id & 0xFFFF) as u16
    } else {
        0x1301 // Default to TLS_AES_128_GCM_SHA256 if cipher is null
    };

    ex_data.events.push_back(TlsEvent::ReadSecret(crypto_level, vec, cipher_suite));
    1
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> i32 {
    let ex_data_ptr = ffi::SSL_get_ex_data(ssl, get_ex_data_index()) as *mut ExData;
    if ex_data_ptr.is_null() {
        return 0;
    }
    let ex_data = &mut *ex_data_ptr;

    let slice = std::slice::from_raw_parts(secret, secret_len);
    let vec = slice.to_vec();

    let crypto_level = match level {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => CryptoLevel::Initial,
        ffi::ssl_encryption_level_t::ssl_encryption_early_data => CryptoLevel::ZeroRTT,
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => CryptoLevel::Handshake,
        ffi::ssl_encryption_level_t::ssl_encryption_application => CryptoLevel::OneRTT,
        _ => return 0,
    };

    // Extract cipher suite ID from SSL_CIPHER
    let cipher_suite = if !cipher.is_null() {
        let full_id = ffi::SSL_CIPHER_get_id(cipher);
        (full_id & 0xFFFF) as u16
    } else {
        0x1301 // Default to TLS_AES_128_GCM_SHA256 if cipher is null
    };

    ex_data.events.push_back(TlsEvent::WriteSecret(crypto_level, vec, cipher_suite));
    1
}

unsafe extern "C" fn add_handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> i32 {
    let ex_data_ptr = ffi::SSL_get_ex_data(ssl, get_ex_data_index()) as *mut ExData;
    if ex_data_ptr.is_null() {
        return 0;
    }
    let ex_data = &mut *ex_data_ptr;
    
    let slice = std::slice::from_raw_parts(data, len);
    let vec = slice.to_vec();
    
    let crypto_level = match level {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => CryptoLevel::Initial,
        ffi::ssl_encryption_level_t::ssl_encryption_early_data => CryptoLevel::ZeroRTT,
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => CryptoLevel::Handshake,
        ffi::ssl_encryption_level_t::ssl_encryption_application => CryptoLevel::OneRTT,
        _ => return 0,
    };
    
    ex_data.events.push_back(TlsEvent::WriteData(crypto_level, vec));
    1
}

unsafe extern "C" fn flush_flight(_ssl: *mut ffi::SSL) -> i32 {
    1
}

unsafe extern "C" fn send_alert(
    _ssl: *mut ffi::SSL,
    _level: ffi::ssl_encryption_level_t,
    _alert: u8,
) -> i32 {
    1
}
