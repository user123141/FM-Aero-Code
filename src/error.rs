use std::fmt;

#[derive(Debug)]
pub enum AeroError {
    BadMagic,
    BadVersion { got: u8, expected: u8 },
    BadHeaderChecksum,
    Truncated(&'static str),
    PayloadTooLarge { need: usize, capacity: usize },
    EmptyPayload,
    DataCorrupted(String),
    WrongPassword,
    PasswordRequired,
    Io(String),
    Internal(String),
    SignatureInvalid,
    DecompressionBomb { declared: usize, limit: usize },
}

impl fmt::Display for AeroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not an FM Aero Code 2 pattern"),
            Self::BadVersion { got, expected } => write!(f, "version {} (want {})", got, expected),
            Self::BadHeaderChecksum => write!(f, "header checksum failed"),
            Self::Truncated(s) => write!(f, "truncated ({})", s),
            Self::PayloadTooLarge { need, capacity } => write!(f, "{} > {} bytes", need, capacity),
            Self::EmptyPayload => write!(f, "empty payload"),
            Self::DataCorrupted(s) => write!(f, "corrupted: {}", s),
            Self::WrongPassword => write!(f, "wrong password"),
            Self::PasswordRequired => write!(f, "password required"),
            Self::Io(m) => write!(f, "io: {}", m),
            Self::Internal(m) => write!(f, "internal: {}", m),
            Self::SignatureInvalid => write!(f, "signature invalid"),
            Self::DecompressionBomb { declared, limit } => {
                write!(f, "declared {} > limit {}", declared, limit)
            }
        }
    }
}
impl std::error::Error for AeroError {}
pub type AeroResult<T> = Result<T, AeroError>;
impl From<std::io::Error> for AeroError {
    fn from(e: std::io::Error) -> Self { Self::Io(e.to_string()) }
}