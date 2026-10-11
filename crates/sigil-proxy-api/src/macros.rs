/// Defines a wire struct: `Serialize` derived, `Deserialize` through an object-only
/// buffer followed by [`crate::Validate`].
///
/// * `wire_struct!` is closed: unknown fields are rejected.
/// * `wire_struct!(lenient ...)` ignores unknown fields when parsing (bodies the proxy
///   reads from the server) and still emits only the declared fields.
macro_rules! wire_struct {
    (lenient $($rest:tt)*) => {
        wire_struct_impl!([] $($rest)*);
    };
    ($($rest:tt)*) => {
        wire_struct_impl!([#[serde(deny_unknown_fields)]] $($rest)*);
    };
}

macro_rules! wire_struct_impl {
    (
        [$(#[$wa:meta])*]
        $(#[$m:meta])*
        pub struct $name:ident {
            $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, serde::Serialize)]
        pub struct $name {
            $( $(#[$fm])* pub $f : $t ),*
        }

        const _: () = {
            #[derive(serde::Deserialize)]
            $(#[$wa])*
            struct Wire {
                $( $(#[$fm])* $f : $t ),*
            }

            impl<'de> serde::Deserialize<'de> for $name {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    let Wire { $($f),* } =
                        <$crate::helpers::ObjectOnly<Wire> as serde::Deserialize>::deserialize(d)?.0;
                    let value = $name { $($f),* };
                    $crate::Validate::validate(&value)
                        .map_err(|e| <D::Error as serde::de::Error>::custom(e.tagged()))?;
                    Ok(value)
                }
            }
        };
    };
}

/// `Validate` for structs without conditional rules.
macro_rules! no_rules {
    ($($name:ident),* $(,)?) => {
        $(impl $crate::Validate for $name {
            fn validate(&self) -> Result<(), $crate::ValidationError> { Ok(()) }
        })*
    };
}
