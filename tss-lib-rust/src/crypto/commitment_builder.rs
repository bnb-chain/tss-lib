use num_bigint::BigInt;

const PARTS_CAP: usize = 3;
const MAX_PART_SIZE: usize = 1 * 1024 * 1024; // 1 MB

pub struct Builder {
    parts: Vec<Vec<BigInt>>,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            parts: Vec::with_capacity(PARTS_CAP),
        }
    }

    pub fn add_part(&mut self, part: Vec<BigInt>) -> &mut Self {
        self.parts.push(part);
        self
    }

    pub fn secrets(&self) -> Result<Vec<BigInt>, String> {
        if self.parts.len() > PARTS_CAP {
            return Err(format!("Too many commitment parts provided: got {}, max {}", self.parts.len(), PARTS_CAP));
        }
        let mut secrets = Vec::new();
        for part in &self.parts {
            let part_len = part.len();
            if part_len > MAX_PART_SIZE {
                return Err(format!("Commitment part too large: size {}", part_len));
            }
            secrets.push(BigInt::from(part_len));
            secrets.extend_from_slice(part);
        }
        Ok(secrets)
    }
}

pub fn parse_secrets(secrets: &[BigInt]) -> Result<Vec<Vec<BigInt>>, String> {
    if secrets.len() < 2 {
        return Err("Secrets too small".to_string());
    }
    let mut parts = Vec::new();
    let mut i = 0;
    while i < secrets.len() {
        let part_len = secrets[i].to_usize().ok_or("Invalid part length")?;
        if part_len > MAX_PART_SIZE {
            return Err(format!("Commitment part too large: size {}", part_len));
        }
        i += 1;
        if i + part_len > secrets.len() {
            return Err("Not enough data to consume stated data length".to_string());
        }
        parts.push(secrets[i..i + part_len].to_vec());
        i += part_len;
    }
    Ok(parts)
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_builder_secrets() {
        let mut builder = Builder::new();
        builder.add_part(vec![1.to_bigint().unwrap(), 2.to_bigint().unwrap()]);
        let secrets = builder.secrets();
        assert!(secrets.is_ok());
    }

    #[test]
    fn test_parse_secrets() {
        let secrets = vec![2.to_bigint().unwrap(), 1.to_bigint().unwrap(), 2.to_bigint().unwrap()];
        let parsed = parse_secrets(&secrets);
        assert!(parsed.is_ok());
    }
}
