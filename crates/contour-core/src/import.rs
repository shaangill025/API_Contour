//! Internal import boundary. Callers must authorize operation, selection and names.
use crate::{DeclaredContract, OperationKey};
use std::fmt;
pub const MAX_IMPORT_BYTES: usize = 5 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    Size,
    Invalid,
    UnsupportedFormat,
    Selection,
    Reference,
    Name,
    Graph,
}
impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ImportError {}
/// Trusted selector, separate from an untrusted public import request.
pub struct ImportSelection<'a> {
    pub source_path: &'a str,
    pub media_type: &'a str,
    /// None selects requestBody; Some selects this exact response key.
    pub response_status: Option<&'a str>,
}
pub fn import_declared(
    format: &str,
    bytes: &[u8],
    operation: OperationKey<'_>,
    selection: ImportSelection<'_>,
    approved_names: &[&str],
) -> Result<DeclaredContract, ImportError> {
    if format != "openapi_json" {
        return Err(ImportError::UnsupportedFormat);
    }
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Size);
    }
    validate_names(approved_names)?;
    let input = crate::import_json::parse(bytes)?;
    crate::import_openapi::convert(&input, operation, selection, approved_names)
}
pub(crate) fn validate_names(approved_names: &[&str]) -> Result<(), ImportError> {
    if approved_names.len() > 256
        || approved_names
            .iter()
            .any(|n| n.is_empty() || n.chars().take(65).count() > 64)
    {
        return Err(ImportError::Name);
    }
    Ok(())
}
