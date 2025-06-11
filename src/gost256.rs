use botan::{Privkey, Pubkey, RandomNumberGenerator, MPI};

/// Ed25519 key pair
pub struct KeyPair {
    pub secret_key: Privkey,
    pub public_key: Pubkey,
}

impl KeyPair {
    /// Generates new Ed25519 key pair
    #[inline(always)]
    pub fn generate() -> Self {
        let mut rng = RandomNumberGenerator::new_system().unwrap();

        Self::from(Privkey::create("GOST-34.10-2012-256", "", &mut rng).unwrap())
    }

    /// Signs a serialized TL representation of data
    #[inline(always)]
    #[cfg(feature = "tl-proto")]
    pub fn sign<T: tl_proto::TlWrite>(&self, data: T) -> [u8; 64] {
        let mut rng = RandomNumberGenerator::new_system().unwrap();
        let mut message = Vec::with_capacity(data.max_size_hint());

        data.write_to(&mut message);

        self.secret_key
            .sign(&message, "Pure", &mut rng)
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// Signs raw bytes
    #[inline(always)]
    pub fn sign_raw(&self, data: &[u8]) -> [u8; 64] {
        let mut rng = RandomNumberGenerator::new_system().unwrap();

        self.secret_key
            .sign(data, "Pure", &mut rng)
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// Computes shared secret using x25519
    #[inline(always)]
    pub fn compute_shared_secret(&self, _other_public_key: &PublicKey) -> [u8; 32] {
        unimplemented!()
    }
}

impl From<Privkey> for KeyPair {
    fn from(secret_key: Privkey) -> Self {
        let public_key = secret_key.pubkey().unwrap();
        Self {
            secret_key,
            public_key,
        }
    }
}

/// Ed25519 public key
pub struct PublicKey(Pubkey);

impl PublicKey {
    /// Tries to create public key from
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let public_x = MPI::new_from_bytes(&bytes[..32]).unwrap();
        let public_y = MPI::new_from_bytes(&bytes[32..]).unwrap();
        let pk = Pubkey::load_ecdsa(&public_x, &public_y, "gost_256A").unwrap();

        Some(Self(pk))
    }

    #[inline(always)]
    #[cfg(feature = "tl-proto")]
    pub fn from_tl(tl: crate::tl::PublicKey<'_>) -> Option<Self> {
        match tl {
            crate::tl::PublicKey::Gost256 { key } => Self::from_bytes(*key),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 64] {
        let public_x = self.0.get_field("public_x").unwrap().to_bin().unwrap();
        let public_y = self.0.get_field("public_y").unwrap().to_bin().unwrap();

        assert_eq!(public_x.len(), 32);
        assert_eq!(public_y.len(), 32);

        let mut bytes = [0; 64];

        bytes[..32].copy_from_slice(&public_x);
        bytes[32..].copy_from_slice(&public_y);

        bytes
    }

    /// Verifies message signature using its TL representation
    ///
    /// NOTE: `[u8]` is representation differently in TL. Use [PublicKey::verify_raw] if
    /// you need to verify raw bytes signature
    #[cfg(feature = "tl-proto")]
    pub fn verify<T: tl_proto::TlWrite>(&self, message: T, signature: &[u8; 64]) -> bool {
        let mut data = Vec::with_capacity(message.max_size_hint());

        message.write_to(&mut data);

        self.0.verify(&data, signature, "Pure").unwrap()
    }

    /// Verifies message signature as it is
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.0.verify(message, signature, "Pure").unwrap()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 128];
        hex::encode_to_slice(self.to_bytes(), &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl std::fmt::Debug for PublicKey {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Copy, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0
    }
}
