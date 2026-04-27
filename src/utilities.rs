pub mod slashstepql;
pub mod route_handler_utilities;

// TODO: Fix deserializer.
fn deserialize_as_value<'de, D>(deserializer: D) -> Result<Option<Option<i32>>, D::Error>
where
  D: Deserializer<'de>,
{
    let opt: Option<Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None), // Field missing
        Some(Value::Null) => Ok(Some(None)), // Present, but null
        Some(v) => {
            let inner = serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(Some(Some(inner))) // Present and valid
        }
    }
}