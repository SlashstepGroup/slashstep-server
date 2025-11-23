use std::fmt;
use std::error::Error;

/// An error that occurs when a resource does not exist.
#[derive(Debug)]
pub struct ResourceNotFoundError<'a> {

  /// The type of the resource.
  pub resource_type: &'a str,

  /// The ID of the resource.
  pub resource_id: &'a str

}

impl Error for ResourceNotFoundError<'_> {}

impl fmt::Display for ResourceNotFoundError<'_> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "A resource with the ID \"{}\" does not exist.", self.resource_id)
  }
}