use pg_escape::quote_identifier;
use postgres_types::ToSql;
use regex::Regex;
use uuid::Uuid;

use crate::errors::slashstepql_invalid_limit_error::SlashstepQLInvalidLimitError;

pub struct SlashstepQLSanitizedFilter {
  pub parameters: Vec<Box<dyn ToSql + Sync>>,
  pub where_clause: Option<String>,
  pub limit: Option<i64>,
  pub offset: Option<i64>
}

pub struct SlashstepQLFilterSanitizer;

#[derive(Debug)]
pub enum SlashstepQLSanitizeError {
  InvalidFilterSyntaxError(String),
  InvalidQueryError(()),
  InvalidFieldError(String),
  RegexError(regex::Error),
  ParseIntError(std::num::ParseIntError),
  InvalidOffsetError(String),
  SlashstepQLInvalidLimitError(SlashstepQLInvalidLimitError),
  UuidParseError(uuid::Error)
}

impl From<uuid::Error> for SlashstepQLSanitizeError {
  fn from(error: uuid::Error) -> Self {
    SlashstepQLSanitizeError::UuidParseError(error)
  }
}

impl From<std::num::ParseIntError> for SlashstepQLSanitizeError {
  fn from(error: std::num::ParseIntError) -> Self {
    SlashstepQLSanitizeError::ParseIntError(error)
  }
}

impl From<regex::Error> for SlashstepQLSanitizeError {
  fn from(error: regex::Error) -> Self {
    SlashstepQLSanitizeError::RegexError(error)
  }
}

pub struct SlashstepQLSanitizeFunctionOptions {
  pub filter: String,
  pub allowed_fields: Vec<String>,
  pub default_limit: Option<i64>,
  pub maximum_limit: Option<i64>,
  pub should_ignore_limit: bool,
  pub should_ignore_offset: bool,
  pub uuid_fields: Vec<String>
}

impl SlashstepQLFilterSanitizer {

  pub fn sanitize(options: &SlashstepQLSanitizeFunctionOptions) -> Result<SlashstepQLSanitizedFilter, SlashstepQLSanitizeError> {

    let mut parameters: Vec<Box<dyn ToSql + Sync>> = Vec::new();
    let mut where_clause = String::new();
    let mut raw_filter = options.filter.to_string();
    let mut offset = None;
    let mut limit = options.default_limit;

    while raw_filter.len() > 0 {

      // Remove unnecessary whitespace.
      raw_filter = raw_filter.trim().to_string();

      const SEARCH_REGEX_PATTERN: &str = r#"^((?<openParenthesis>\()|(?<closedParenthesis>\))|(?<and>and)|(?<or>or)|(?<not>not)|(?<assignment>(?<key>\w+) *(?<operator>is|~|~\*|!~|!~\*|=|>|<|>=|<=) *(("(?<stringDoubleQuotes>[^"\\]*(?:\\.[^"\\]*)*)")|(('(?<stringSingleQuotes>[^'\\]*(?:\\.[^'\\]*)*)'))|(?<number>(\d+\.?\d*|(\.\d+)))|(?<boolean>(true|false))|(?<null>null)))|(limit ((?<limit>\d+)))|(offset ((?<offset>\d+))))"#;
      let search_regex = Regex::new(SEARCH_REGEX_PATTERN)?;
      let regex_captures = search_regex.captures(&raw_filter);

      if let Some(regex_captures) = regex_captures {

        if regex_captures.name("openParenthesis").is_some() {

          where_clause.push_str("(");

        } else if regex_captures.name("closedParenthesis").is_some() {

          where_clause.push_str(")");

        } else if regex_captures.name("and").is_some() {

          where_clause.push_str(" and ");

        } else if regex_captures.name("or").is_some() {

          where_clause.push_str(" or ");

        } else if regex_captures.name("not").is_some() {

          where_clause.push_str(" not ");

        } else if regex_captures.name("assignment").is_some() {

          // Ensure the key is a valid identifier. Very important to prevent SQL injection.
          if let Some(original_key) = regex_captures.name("key").and_then(|string_match| Some(string_match.as_str().to_string())) {

            let field = original_key.as_str().to_string();
            if !options.allowed_fields.contains(&field) {

              return Err(SlashstepQLSanitizeError::InvalidFieldError(field));

            }

            let string_value = regex_captures.name("stringDoubleQuotes").or(regex_captures.name("stringSingleQuotes")).and_then(|string_match| Some(string_match.as_str().to_string()));
            let number_value = regex_captures.name("numberValue").and_then(|string_match| Some(string_match.as_str().parse::<i64>().ok()?));
            let boolean_value = regex_captures.name("booleanValue").and_then(|string_match| Some(string_match.as_str().parse::<bool>().ok()?));
            let operator = regex_captures.name("operator").and_then(|string_match| Some(string_match.as_str().to_string()));
            let has_null_value = regex_captures.name("nullValue").is_some();

            if let Some(operator) = operator {

              let identifier = quote_identifier(&original_key);
              let formatted_value = format!("${}", parameters.len() + 1);
              let where_value = if has_null_value { "NULL" } else { formatted_value.as_str() };
              where_clause.push_str(&format!("{} {} {}", identifier, operator, where_value));

              if !has_null_value {

                if let Some(string_value) = string_value {

                  if options.uuid_fields.contains(&original_key) {

                    let uuid = Uuid::parse_str(string_value.as_str())?;
                    parameters.push(Box::new(uuid));

                  } else {

                    parameters.push(Box::new(string_value));

                  }

                } else if let Some(number_value) = number_value {

                  parameters.push(Box::new(number_value));

                } else if let Some(boolean_value) = boolean_value {

                  parameters.push(Box::new(boolean_value));

                }

              }
              
            }

          } else {


          }

        } else if regex_captures.name("limit").is_some() {

          // Ensure the limit is a valid integer.
          if let Some(limit_string) = regex_captures.name("limit") {

            let maximum_limit_result = options.maximum_limit;
            if let Ok(new_limit) = limit_string.as_str().parse::<i64>() {
              
              if let Some(maximum_limit) = maximum_limit_result {

                if new_limit > maximum_limit || new_limit < 0 {

                  let error = SlashstepQLInvalidLimitError {
                    limit_string: limit_string.as_str().to_string(),
                    maximum_limit: maximum_limit_result
                  };
                  return Err(SlashstepQLSanitizeError::SlashstepQLInvalidLimitError(error));

                }

              } else {

                limit = Some(new_limit);

              }

            } else {

              let error = SlashstepQLInvalidLimitError {
                limit_string: limit_string.as_str().to_string(),
                maximum_limit: maximum_limit_result
              };
              return Err(SlashstepQLSanitizeError::SlashstepQLInvalidLimitError(error));

            }

          }

        } else if regex_captures.name("offset").is_some() {

          // Ensure the offset is a valid integer.
          if let Some(offset_string) = regex_captures.name("offset") {

            if let Ok(new_offset) = offset_string.as_str().parse::<i64>() {
              
              offset = Some(new_offset);

            } else {

              return Err(SlashstepQLSanitizeError::InvalidOffsetError(format!("Invalid offset \"{}\" in filter query. It must be a non-negative integer.", offset_string.as_str())));

            }

          }

        } else {

          return Err(SlashstepQLSanitizeError::InvalidQueryError(()));

        }

      } else {

        println!("Regex capture group: {:?}", regex_captures);
        return Err(SlashstepQLSanitizeError::InvalidQueryError(()));

      }

      if let Some(end) = search_regex.find(&raw_filter) {

        raw_filter = raw_filter[end.len()..].to_string();

      }

    }

    return Ok(SlashstepQLSanitizedFilter {
      parameters,
      where_clause: if where_clause.len() > 0 { Some(where_clause) } else { None },
      limit,
      offset
    });

  }

}