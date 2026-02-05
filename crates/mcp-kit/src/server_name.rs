use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerName(Box<str>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerNameError {
    #[error("server name must not be empty")]
    Empty,
    #[error("invalid server name: {0} (allowed: [A-Za-z0-9_-]+)")]
    Invalid(String),
}

impl ServerName {
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
        Ok(Self(name.into()))
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
        value.0.into()
    }
}
