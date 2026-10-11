/// Defines a closed wire struct: `Serialize` derived, `Deserialize` strict
/// (unknown fields rejected, objects only) followed by [`crate::Validate`].
macro_rules! wire_struct {
    (
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
            #[serde(deny_unknown_fields)]
            struct Wire {
                $( $(#[$fm])* $f : $t ),*
            }

            impl<'de> serde::Deserialize<'de> for $name {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    let Wire { $($f),* } =
                        <$crate::helpers::ObjectOnly<Wire> as serde::Deserialize>::deserialize(d)?.0;
                    let value = $name { $($f),* };
                    $crate::Validate::validate(&value)
                        .map_err(<D::Error as serde::de::Error>::custom)?;
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
