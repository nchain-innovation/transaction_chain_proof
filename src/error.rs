use ark_std::error::Error as arkErr;

pub type ArkError = Box<dyn arkErr + 'static>;

/// Snark Errors
#[derive(Debug)]
pub enum SnarkError {
    /// Error during setup
    Setup(ArkError),
    /// Error during proof generation
    ProofGeneration(ArkError),
    /// Error during proof verification
    Verification(ArkError),
}

pub struct SnarkSetup;
pub struct SnarkProofGeneration;
pub struct SnarkVerification;

impl From<(ArkError, SnarkSetup)> for SnarkError {
    fn from((error, _): (ArkError, SnarkSetup)) -> Self {
        SnarkError::Setup(error)
    }
}

impl From<(ArkError, SnarkProofGeneration)> for SnarkError {
    fn from((error, _): (ArkError, SnarkProofGeneration)) -> Self {
        SnarkError::ProofGeneration(error)
    }
}

impl From<(ArkError, SnarkVerification)> for SnarkError {
    fn from((error, _): (ArkError, SnarkVerification)) -> Self {
        SnarkError::Verification(error)
    }
}
