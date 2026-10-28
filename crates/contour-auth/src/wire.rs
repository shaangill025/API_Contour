use serde::{Deserialize, Deserializer, de};
use std::{fmt, marker::PhantomData};

pub(crate) struct Object<T>(pub(crate) T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Map<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Map<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("object")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        decoder.deserialize_map(Map(PhantomData))
    }
}

pub(crate) struct Bounded<T, const N: usize>(pub(crate) Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct List<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> de::Visitor<'de> for List<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded array")
            }
            fn visit_seq<S: de::SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let mut values = Vec::new();
                loop {
                    if values.len() == N {
                        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                            return Err(de::Error::custom("array limit"));
                        }
                        return Ok(Bounded(values));
                    }
                    match sequence.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(Bounded(values)),
                    }
                }
            }
        }
        decoder.deserialize_seq(List(PhantomData))
    }
}

// Missing optional fields are allowed, explicitly malformed/null values are not.
pub(crate) fn present<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(decoder).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub(crate) alg: String,
    pub(crate) kid: String,
    #[serde(default, deserialize_with = "present")]
    pub(crate) typ: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Jwks {
    pub(crate) keys: Bounded<Object<Jwk>, 32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Jwk {
    pub(crate) kty: String,
    pub(crate) kid: String,
    pub(crate) n: String,
    pub(crate) e: String,
    #[serde(default, deserialize_with = "present")]
    pub(crate) alg: Option<String>,
    #[serde(default, deserialize_with = "present", rename = "use")]
    pub(crate) usage: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub(crate) key_ops: Option<Bounded<String, 1>>,
    // Certificate metadata is accepted as public data but never used as trust.
    #[serde(default, deserialize_with = "present", rename = "x5c")]
    pub(crate) _certificates: Option<Bounded<String, 8>>,
    #[serde(default, deserialize_with = "present", rename = "x5t")]
    pub(crate) _thumbprint: Option<String>,
    #[serde(default, deserialize_with = "present", rename = "x5t#S256")]
    pub(crate) _sha256_thumbprint: Option<String>,
}

pub(crate) struct Audience(pub(crate) Vec<String>);
impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Aud;
        impl<'de> de::Visitor<'de> for Aud {
            type Value = Audience;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("audience string or bounded string array")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if !text(value, 256) {
                    return Err(E::custom("audience limit"));
                }
                Ok(Audience(vec![value.to_owned()]))
            }
            fn visit_seq<S: de::SeqAccess<'de>>(
                self,
                sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let values = Bounded::<String, 16>::deserialize(
                    de::value::SeqAccessDeserializer::new(sequence),
                )?
                .0;
                if values.is_empty() || values.iter().any(|value| !text(value, 256)) {
                    return Err(de::Error::custom("audience limit"));
                }
                Ok(Audience(values))
            }
        }
        decoder.deserialize_any(Aud)
    }
}

#[derive(Deserialize)]
pub(crate) struct Claims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: Audience,
    pub(crate) exp: u64,
    pub(crate) iat: u64,
    pub(crate) nonce: String,
    #[serde(default, deserialize_with = "present")]
    pub(crate) nbf: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    pub(crate) azp: Option<String>,
}
pub(crate) fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
