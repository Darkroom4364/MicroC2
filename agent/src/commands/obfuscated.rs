/// XOR obfuscate a string with a key (agent_id)
pub fn xor_obfuscate(data: &str, key: &str) -> String {
    if key.is_empty() {
        return data.bytes().map(|b| format!("{:02x}", b)).collect();
    }
    let key_bytes = key.as_bytes();
    data.bytes()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// XOR deobfuscate a hex string with a key (agent_id)
pub fn xor_deobfuscate(hex: &str, key: &str) -> Option<String> {
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
        .collect();
    if key.is_empty() {
        return bytes.ok().map(|v| v.into_iter().map(|b| b as char).collect());
    }
    let key_bytes = key.as_bytes();
    bytes.ok().map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, b)| (b ^ key_bytes[i % key_bytes.len()]) as char)
            .collect()
    })
}
