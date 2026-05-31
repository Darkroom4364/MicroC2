/// XOR obfuscate a string with a key (agent_id)
pub fn xor_obfuscate(data: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    data.bytes()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// XOR deobfuscate a hex string with a key (agent_id)
pub fn xor_deobfuscate(hex: &str, key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    bytes.ok().map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, b)| (b ^ key_bytes[i % key_bytes.len()]) as char)
            .collect()
    })
}

pub fn obfuscate_command(cmd: &str) -> String {
    let mapping = [
        ('a', 'ᵃ'),
        ('e', 'ᵉ'),
        ('o', 'ᵒ'),
        ('i', 'ᶦ'),
        ('s', 'ˢ'),
        ('l', 'ˡ'),
        ('t', 'ᵗ'),
        ('n', 'ⁿ'),
        ('r', 'ʳ'),
        ('d', 'ᵈ'),
    ];
    let mut result = String::with_capacity(cmd.len());
    for c in cmd.chars() {
        if let Some(&(_, sub)) = mapping.iter().find(|&&(orig, _)| orig == c) {
            result.push(sub);
        } else {
            result.push(c);
        }
    }
    result
}

pub fn random_case(s: &str, probability: f32) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rand::random::<f32>() < probability {
                if rand::random::<bool>() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

pub fn random_quote_insertion(s: &str, probability: f32) -> String {
    //let mut rng = rand::rng();
    let mut result = String::new();
    for word in s.split_whitespace() {
        if rand::random::<f32>() < probability {
            result.push('"');
            result.push_str(word);
            result.push('"');
        } else {
            result.push_str(word);
        }
        result.push(' ');
    }
    result.trim_end().to_string()
}

pub fn random_char_insertion(s: &str, probability: f32) -> String {
    let mut result = String::new();
    for c in s.chars() {
        result.push(c);
        if rand::random::<f32>() < probability {
            // Insert a random ASCII symbol
            let rand_char = (33u8 + (rand::random::<u8>() % 15)) as char;
            result.push(rand_char);
        }
    }
    result
}
