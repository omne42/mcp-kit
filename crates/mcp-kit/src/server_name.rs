use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerName(Arc<str>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServerNameError {
    #[error("server name must not be empty")]
    Empty,
    #[error("invalid server name: {0} (allowed: [A-Za-z0-9_-]+)")]
    Invalid(String),
}

impl ServerName {
    /// Parse and validate an MCP server name.
    ///
    /// Note: this trims leading/trailing ASCII whitespace before validation. In other words,
    /// `" a "` and `"a"` normalize to the same `ServerName`.
    pub fn parse(name: impl AsRef<str>) -> Result<Self, ServerNameError> {
        let name = name.as_ref().trim();
        if name.is_empty() {
            return Err(ServerNameError::Empty);
        }
        if !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        {
            return Err(ServerNameError::Invalid(name.to_string()));
        }
        Ok(Self(Arc::from(name)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for ServerName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ServerName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Serialize for ServerName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ServerName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(name).map_err(D::Error::custom)
    }
}

impl TryFrom<&str> for ServerName {
    type Error = ServerNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for ServerName {
    type Error = ServerNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ServerName> for String {
    fn from(value: ServerName) -> Self {
        value.0.as_ref().to_string()
    }
}
