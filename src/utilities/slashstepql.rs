use std::fmt;
use pg_escape::{quote_identifier, quote_literal};
use postgres_types::ToSql;
use regex::{RegexBuilder};
use thiserror::Error;
use std::error::Error;
use crate::resources::access_policy::IndividualPrincipal;

/// An error that occurs when a resource does not exist.
#[derive(Debug)]
pub struct SlashstepQLInvalidLimitError {

  pub limit_string: String,
  
  pub maximum_limit: Option<i64>

}

impl Error for SlashstepQLInvalidLimitError {}

impl fmt::Display for SlashstepQLInvalidLimitError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Invalid limit \"{}\" in filter query. It must be a non-negative integer{}.", self.limit_string, if let Some(maximum_limit) = self.maximum_limit { format!(" and must be less than or equal to {}", maximum_limit) } else { "".to_string() })
  }
}

pub struct SlashstepQLSanitizedFilter {
  pub parameters: Vec<(String, SlashstepQLParameterType)>,
  pub where_clause: Option<String>,
  pub limit: Option<i64>,
  pub offset: Option<i64>
}

pub enum SlashstepQLParameterType {
  String(String),
  Number(i64),
  Boolean(bool)
}

pub struct SlashstepQLFilterSanitizer;

#[derive(Debug, Error)]
pub enum SlashstepQLError {
  #[error("Invalid filter syntax: {0}")]
  InvalidFilterSyntaxError(String),
  #[error("Invalid query.")]
  InvalidQueryError(()),
  #[error("Invalid field: {0}")]
  InvalidFieldError(String),
  #[error("Invalid regex: {0}")]
  RegexError(#[from] regex::Error),
  #[error("Invalid integer: {0}")]
  ParseIntError(#[from] std::num::ParseIntError),
  #[error("Invalid offset: {0}")]
  InvalidOffsetError(String),
  #[error("Invalid limit: {0}")]
  SlashstepQLInvalidLimitError(SlashstepQLInvalidLimitError),
  #[error("String parser error: {0}")]
  StringParserError(String),
}

pub struct SlashstepQLSanitizeFunctionOptions {
  pub filter: String,
  pub allowed_fields: Vec<String>,
  pub default_limit: Option<i64>,
  pub maximum_limit: Option<i64>,
  pub should_ignore_limit: bool,
  pub should_ignore_offset: bool
}

pub type SlashstepQLParsedParameter<'a> = Box<dyn ToSql + Sync + Send + 'a>;
pub type SlashstepQLParsedParameters<'a> = Vec<SlashstepQLParsedParameter<'a>>;

impl SlashstepQLFilterSanitizer {

  pub fn sanitize(options: &SlashstepQLSanitizeFunctionOptions) -> Result<SlashstepQLSanitizedFilter, SlashstepQLError> {

    let mut parameters = Vec::new();
    let mut where_clause = String::new();
    let mut raw_filter = options.filter.to_string();
    let mut offset = None;
    let mut limit = options.default_limit;

    while raw_filter.len() > 0 {

      // Remove unnecessary whitespace.
      raw_filter = raw_filter.trim().to_string();

      const SEARCH_REGEX_PATTERN: &str = r#"^((?<openParenthesis>\()|(?<closedParenthesis>\))|(?<and>and)|(?<or>or)|(?<not>not)|(?<assignment>(?<key>\w+) *(?<operator>is|~|~\*|!~|!~\*|=|>|<|>=|<=) *(("(?<stringDoubleQuotes>[^"\\]*(?:\\.[^"\\]*)*)")|(('(?<stringSingleQuotes>[^'\\]*(?:\\.[^'\\]*)*)'))|(?<number>(\d+\.?\d*|(\.\d+)))|(?<boolean>(true|false))|(?<null>null)))|(limit ((?<limit>\d+)))|(offset ((?<offset>\d+))))"#;
      let search_regex = RegexBuilder::new(SEARCH_REGEX_PATTERN)
        .case_insensitive(true)
        .build()?;
      let regex_captures = search_regex.captures(&raw_filter);

      if let Some(regex_captures) = regex_captures {

        if regex_captures.name("openParenthesis").is_some() {

          where_clause.push_str("(");

        } else if regex_captures.name("closedParenthesis").is_some() {

          where_clause.push_str(")");

        } else if regex_captures.name("and").is_some() {

          where_clause.push_str(" AND ");

        } else if regex_captures.name("or").is_some() {

          where_clause.push_str(" OR ");

        } else if regex_captures.name("not").is_some() {

          where_clause.push_str(" NOT ");

        } else if regex_captures.name("assignment").is_some() {

          // Ensure the key is a valid identifier. Very important to prevent SQL injection.
          if let Some(original_key) = regex_captures.name("key").and_then(|string_match| Some(string_match.as_str().to_string())) {

            let field = original_key.as_str().to_string();
            if !options.allowed_fields.contains(&field) {

              return Err(SlashstepQLError::InvalidFieldError(field));

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

                  parameters.push((original_key.to_string(), SlashstepQLParameterType::String(string_value)));

                } else if let Some(number_value) = number_value {

                  parameters.push((original_key.to_string(), SlashstepQLParameterType::Number(number_value)));

                } else if let Some(boolean_value) = boolean_value {

                  parameters.push((original_key.to_string(), SlashstepQLParameterType::Boolean(boolean_value)));

                }

              }
              
            }

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
                  return Err(SlashstepQLError::SlashstepQLInvalidLimitError(error));

                }

              } else {

                limit = Some(new_limit);

              }

            } else {

              let error = SlashstepQLInvalidLimitError {
                limit_string: limit_string.as_str().to_string(),
                maximum_limit: maximum_limit_result
              };
              return Err(SlashstepQLError::SlashstepQLInvalidLimitError(error));

            }

          }

        } else if regex_captures.name("offset").is_some() {

          // Ensure the offset is a valid integer.
          if let Some(offset_string) = regex_captures.name("offset") {

            if let Ok(new_offset) = offset_string.as_str().parse::<i64>() {
              
              offset = Some(new_offset);

            } else {

              return Err(SlashstepQLError::InvalidOffsetError(format!("Invalid offset \"{}\" in filter query. It must be a non-negative integer.", offset_string.as_str())));

            }

          }

        } else {

          return Err(SlashstepQLError::InvalidQueryError(()));

        }

      } else {

        return Err(SlashstepQLError::InvalidQueryError(()));

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

  pub fn build_query_from_sanitized_filter(
    sanitized_filter: &SlashstepQLSanitizedFilter, 
    individual_principal: Option<&IndividualPrincipal>,
    resource_type: &str,
    table_name: &str,
    get_resource_action_name: &str,
    should_count: bool
  ) -> String {

    let where_clause = sanitized_filter.where_clause.clone().unwrap_or("".to_string());
    let where_clause = match individual_principal {
      
      Some(individual_principal) => {
        
        let additional_condition = match individual_principal {

          IndividualPrincipal::User(user_id) => format!("can_principal_get_resource('User', {}, {}, {}.id, {})", quote_literal(&user_id.to_string()), quote_literal(resource_type), &table_name, quote_literal(get_resource_action_name)),

          IndividualPrincipal::App(app_id) => format!("can_principal_get_resource('App', {}, {}, {}.id, {})", quote_literal(&app_id.to_string()), quote_literal(resource_type), &table_name, quote_literal(get_resource_action_name))

        };

        if where_clause == "" { 
          
          additional_condition 
        
        } else { 
          
          format!("({}) AND {}", where_clause, additional_condition)
        
        }

      },

      None => where_clause

    };
    let where_clause = if where_clause == "" { where_clause } else { format!(" where {}", where_clause) };
    let limit_clause = sanitized_filter.limit.and_then(|limit| Some(format!(" limit {}", limit))).unwrap_or("".to_string());
    let offset_clause = sanitized_filter.offset.and_then(|offset| Some(format!(" offset {}", offset))).unwrap_or("".to_string());
    let query = format!("select {} from {}{}{}{}", if should_count { "count(*)" } else { "*" }, table_name, where_clause, limit_clause, offset_clause);

    return query;

  }

  
}

pub fn add_parameter_to_query<T: ToSql + Sync + Clone + Send + 'static>(mut parameter_boxes: Vec<Box<dyn ToSql + Sync + Send>>, mut query: String, key: &str, parameter_value: Option<&T>) -> (Vec<Box<dyn ToSql + Sync + Send>>, String) {

  let parameter_value = parameter_value.and_then(|parameter_value| Some(parameter_value.clone()));
  if let Some(parameter_value) = parameter_value {

    query.push_str(format!("{}{} = ${}", if parameter_boxes.len() > 0 { ", " } else { "" }, key, parameter_boxes.len() + 1).as_str());
    parameter_boxes.push(Box::new(parameter_value));

  }
  
  return (parameter_boxes, query);

}

pub fn parse_parameters<'a>(
  slashstepql_parameters: &'a Vec<(String, SlashstepQLParameterType)>, 
  string_parser: impl Fn(&'a str, &'a str) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError>
) -> Result<SlashstepQLParsedParameters<'a>, SlashstepQLError> {

  let mut parsed_parameters: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();

  for (key, value) in slashstepql_parameters {

    match value {

      SlashstepQLParameterType::String(string_value) => {
        
        let parsed_value = string_parser(key, string_value)?;
        parsed_parameters.push(parsed_value);

      },

      SlashstepQLParameterType::Number(number_value) => {

        parsed_parameters.push(Box::new(number_value));

      },

      SlashstepQLParameterType::Boolean(boolean_value) => {

        parsed_parameters.push(Box::new(boolean_value));

      }

    }

  }

  return Ok(parsed_parameters);

}