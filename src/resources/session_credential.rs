/*
 *
 * This module defines the implementation and types of a session credential.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */

use crate::{
    resources::{ResourceError, access_policy::AccessPolicyPrincipalType},
    utilities::slashstepql::{
        self, SlashstepQLAssignmentProperties, SlashstepQLAssignmentTranslationResult,
        SlashstepQLError, SlashstepQLFilterSanitizer, SlashstepQLParsedParameter,
        SlashstepQLSanitizeFunctionOptions,
    },
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Header;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub const DEFAULT_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT: i64 = 1000;
pub const ALLOWED_QUERY_KEYS: &[&str] =
    &["id", "user_id", "expiration_date", "creation_ip_address"];
pub const UUID_QUERY_KEYS: &[&str] = &["id", "user_id"];
pub const RESOURCE_NAME: &str = "SessionCredential";
pub const DATABASE_TABLE_NAME: &str = "session_credentials";
pub const GET_RESOURCE_ACTION_NAME: &str = "sessionCredentials.get";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCredentialTokenClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub session_id: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCredential {
    /// The session credential's ID.
    pub id: Uuid,

    /// The session credential's user ID.
    pub user_id: Uuid,

    /// The session credential's session ID.
    pub session_id: Uuid,

    /// The session credential's creation IP address.
    pub creation_ip_address: IpAddr,

    /// The session credential's access token expiration date.
    pub access_token_expiration_date: DateTime<Utc>,

    /// The session credential's refresh token expiration date.
    pub refresh_token_expiration_date: DateTime<Utc>,

    /// The session credential's refreshed session credential ID.
    pub refreshed_session_credential_id: Option<Uuid>,
}

pub struct InitialSessionCredentialProperties {
    /// The session credential's user ID.
    pub user_id: Uuid,

    /// The session credential's session ID.
    pub session_id: Uuid,

    /// The session credential's creation IP address.
    pub creation_ip_address: IpAddr,

    /// The session credential's access token expiration date.
    pub access_token_expiration_date: DateTime<Utc>,

    /// The session credential's refresh token expiration date.
    pub refresh_token_expiration_date: DateTime<Utc>,

    /// The session credential's refreshed session credential ID.
    pub refreshed_session_credential_id: Option<Option<Uuid>>,
}

impl SessionCredential {
    /// Counts the number of roles based on a query.
    pub async fn count(
        query: &str,
        database_pool: &deadpool_postgres::Pool,
        principal_type: Option<&AccessPolicyPrincipalType>,
        principal_id: Option<&Uuid>,
    ) -> Result<i64, ResourceError> {
        // Prepare the query.
        let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
            filter: query.to_string(),
            default_limit: None,
            maximum_limit: None,
            should_ignore_limit: true,
            should_ignore_offset: true,
            translate_assignment: Self::translate_assignment,
        };
        let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
        let database_client = database_pool.get().await?;
        let get_resource_action_id: Uuid = database_client
            .query_one(
                "SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'",
                &[&GET_RESOURCE_ACTION_NAME],
            )
            .await?
            .get(0);
        let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(
            &sanitized_filter,
            principal_type,
            principal_id,
            RESOURCE_NAME,
            DATABASE_TABLE_NAME,
            &get_resource_action_id,
            true,
        )?;
        let parsed_parameters = slashstepql::parse_parameters(
            &sanitized_filter.parameters,
            Self::parse_string_slashstepql_parameters,
        )?;
        let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect();

        // Execute the query.
        let rows = database_client.query_one(&query, &parameters).await?;
        let count = rows.get(0);
        Ok(count)
    }

    /// Gets a field by its ID.
    pub async fn get_by_id(
        id: &Uuid,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let database_client = database_pool.get().await?;
        let query =
            include_str!("../queries/session_credentials/get_session_credential_row_by_id.sql");
        let row = match database_client.query_opt(query, &[&id]).await {
            Ok(row) => match row {
                Some(row) => row,

                None => {
                    return Err(ResourceError::NotFoundError(format!(
                        "A session credential with the ID \"{}\" does not exist.",
                        id
                    )));
                }
            },

            Err(error) => return Err(ResourceError::PostgresError(error)),
        };

        let session_credential = Self::convert_from_row(&row);

        Ok(session_credential)
    }

    /// Converts a row into a session credential.
    fn convert_from_row(row: &postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            session_id: row.get("session_id"),
            creation_ip_address: row.get("creation_ip_address"),
            access_token_expiration_date: row.get("access_token_expiration_date"),
            refresh_token_expiration_date: row.get("refresh_token_expiration_date"),
            refreshed_session_credential_id: row.get("refreshed_session_credential_id"),
        }
    }

    /// Initializes the session_credentials table.
    pub async fn initialize_resource_table(
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<(), ResourceError> {
        let database_client = database_pool.get().await?;
        let query =
            include_str!("../queries/session_credentials/initialize_session_credentials_table.sql");
        database_client.execute(query, &[]).await?;
        Ok(())
    }

    /// Creates a new session credential.
    pub async fn create(
        initial_properties: &InitialSessionCredentialProperties,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<Self, ResourceError> {
        let access_token_expiration_date = match DateTime::from_timestamp_millis(
            initial_properties
                .access_token_expiration_date
                .timestamp_millis(),
        ) {
            Some(expiration_date) => expiration_date,

            None => {
                return Err(ResourceError::DateError(
                    initial_properties.access_token_expiration_date,
                ));
            }
        };
        let refresh_token_expiration_date = match DateTime::from_timestamp_millis(
            initial_properties
                .refresh_token_expiration_date
                .timestamp_millis(),
        ) {
            Some(expiration_date) => expiration_date,

            None => {
                return Err(ResourceError::DateError(
                    initial_properties.refresh_token_expiration_date,
                ));
            }
        };
        let query =
            include_str!("../queries/session_credentials/insert_session_credential_row.sql");
        let parameters: &[&(dyn ToSql + Sync)] = &[
            &initial_properties.session_id,
            &initial_properties.user_id,
            &initial_properties.creation_ip_address,
            &access_token_expiration_date,
            &refresh_token_expiration_date,
            &initial_properties.refreshed_session_credential_id,
        ];
        let database_client = database_pool.get().await?;
        let row = database_client
            .query_one(query, parameters)
            .await
            .map_err(ResourceError::PostgresError)?;

        // Return the session credential.
        let session_credential = Self::convert_from_row(&row);

        Ok(session_credential)
    }

    pub async fn delete(
        &self,
        database_pool: &deadpool_postgres::Pool,
    ) -> Result<(), ResourceError> {
        let database_client = database_pool.get().await?;
        let query =
            include_str!("../queries/session_credentials/delete_session_credential_row_by_id.sql");
        database_client.execute(query, &[&self.id]).await?;

        Ok(())
    }

    pub fn decode_token(
        token: &str,
        public_key: &str,
    ) -> Result<SessionCredentialTokenClaims, ResourceError> {
        let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(public_key.as_ref())?;
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        let token_data = jsonwebtoken::decode::<SessionCredentialTokenClaims>(
            token,
            &decoding_key,
            &validation,
        )?;
        Ok(token_data.claims)
    }

    pub async fn generate_access_token(&self, private_key: &str) -> Result<String, ResourceError> {
        let claims = SessionCredentialTokenClaims {
            sub: self.user_id.to_string(),
            jti: self.id.to_string(),
            exp: self.access_token_expiration_date.timestamp() as usize,
            session_id: self.session_id.to_string(),
            r#type: "Access".to_string(),
        };
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
        let token = jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &encoding_key,
        )?;

        Ok(token)
    }

    pub async fn generate_refresh_token(&self, private_key: &str) -> Result<String, ResourceError> {
        let claims = SessionCredentialTokenClaims {
            sub: self.user_id.to_string(),
            jti: self.id.to_string(),
            exp: self.refresh_token_expiration_date.timestamp() as usize,
            session_id: self.session_id.to_string(),
            r#type: "Refresh".to_string(),
        };
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_ref())?;
        let token = jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &encoding_key,
        )?;

        Ok(token)
    }

    /// Returns a list of roles based on a query.
    pub async fn list(
        query: &str,
        database_pool: &deadpool_postgres::Pool,
        principal_type: Option<&AccessPolicyPrincipalType>,
        principal_id: Option<&Uuid>,
    ) -> Result<Vec<Self>, ResourceError> {
        // Prepare the query.
        let sanitizer_options = SlashstepQLSanitizeFunctionOptions {
            filter: query.to_string(),
            default_limit: Some(DEFAULT_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
            maximum_limit: Some(DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT), // TODO: Make this configurable through resource policies.
            should_ignore_limit: false,
            should_ignore_offset: false,
            translate_assignment: Self::translate_assignment,
        };
        let sanitized_filter = SlashstepQLFilterSanitizer::sanitize(&sanitizer_options)?;
        let database_client = database_pool.get().await?;
        let get_resource_action_id: Uuid = database_client
            .query_one(
                "SELECT id FROM actions WHERE name = $1 AND parent_resource_type = 'Server'",
                &[&GET_RESOURCE_ACTION_NAME],
            )
            .await?
            .get(0);
        let query = SlashstepQLFilterSanitizer::build_query_from_sanitized_filter(
            &sanitized_filter,
            principal_type,
            principal_id,
            RESOURCE_NAME,
            DATABASE_TABLE_NAME,
            &get_resource_action_id,
            false,
        )?;
        let parsed_parameters = slashstepql::parse_parameters(
            &sanitized_filter.parameters,
            Self::parse_string_slashstepql_parameters,
        )?;
        let parameters: Vec<&(dyn ToSql + Sync)> = parsed_parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect();

        // Execute the query.
        let rows = database_client.query(&query, &parameters).await?;
        let session_credentials = rows.iter().map(Self::convert_from_row).collect();
        Ok(session_credentials)
    }

    pub fn is_access_token_expired(&self) -> bool {
        Utc::now() > self.access_token_expiration_date
    }

    pub fn is_refresh_token_expired(&self) -> bool {
        Utc::now() > self.refresh_token_expiration_date
    }

    /// Parses a string into a parameter for a slashstepql query.
    fn parse_string_slashstepql_parameters<'a>(
        key: &'a str,
        value: &'a str,
    ) -> Result<SlashstepQLParsedParameter<'a>, SlashstepQLError> {
        if UUID_QUERY_KEYS.contains(&key) {
            let uuid = match Uuid::parse_str(value) {
                Ok(uuid) => uuid,
                Err(_) => {
                    return Err(SlashstepQLError::StringParserError(format!(
                        "Failed to parse UUID from \"{}\" for key \"{}\".",
                        value, key
                    )));
                }
            };

            return Ok(Box::new(uuid));
        }

        Ok(Box::new(value))
    }

    fn translate_assignment(
        assignment_properties: SlashstepQLAssignmentProperties,
    ) -> Result<SlashstepQLAssignmentTranslationResult, SlashstepQLError> {
        // TODO: Later, this can be used for parsing in-query functions (i.e. "getCurrentUser()").

        // If the key is already a valid column in the items table, then we can directly translate the assignment without needing to account for dynamic keys.
        if ALLOWED_QUERY_KEYS.contains(&assignment_properties.key.as_str()) {
            return Ok(slashstepql::translate_normal_assignment(
                assignment_properties,
            ));
        }

        Err(SlashstepQLError::InvalidFieldError(
            assignment_properties.key,
        ))
    }
}
