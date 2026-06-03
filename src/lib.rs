#![warn(clippy::unwrap_used)]

pub mod middleware;
pub mod predefinitions;
pub mod resources;
pub mod routes;
pub mod utilities;

pub const DEFAULT_APP_PORT: u16 = 8080;
pub const DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT: u32 = 5;

use deadpool_postgres::tokio_postgres;
use postgres::NoTls;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use opensearch::{OpenSearch, http::transport::SingleNodeConnectionPool};
use tracing::{Subscriber, error, warn};
use url::Url;
use uuid::Uuid;
use tokio::sync::mpsc;

use crate::resources::{
    ResourceError,
    access_policy::AccessPolicy,
    action::Action,
    action_log_entry::ActionLogEntry,
    app::App,
    app_authorization::AppAuthorization,
    app_authorization_credential::AppAuthorizationCredential,
    app_credential::AppCredential,
    configuration::{Configuration, EditableConfigurationProperties},
    delegation_policy::DelegationPolicy,
    field::Field,
    field_choice::FieldChoice,
    field_value::FieldValue,
    group::Group,
    http_transaction::HTTPTransaction,
    item::Item,
    item_connection::ItemConnection,
    item_connection_type::ItemConnectionType,
    item_type::ItemType,
    item_type_icon::ItemTypeIcon,
    iteration::Iteration,
    membership::{
        InitialMembershipProperties, Membership, MembershipParentResourceType,
        MembershipPrincipalType,
    },
    membership_invitation::MembershipInvitation,
    milestone::Milestone,
    oauth_authorization::OAuthAuthorization,
    password_reset_authorization::PasswordResetAuthorization,
    project::Project,
    role::{PredefinedRoleType, Role, RoleParentResourceType},
    server_log_entry::ServerLogEntry,
    session::Session,
    session_credential::SessionCredential,
    status::Status,
    user::{InitialUserProperties, User},
    view::View,
    view_field::ViewField,
    webhook::Webhook,
    workspace::Workspace,
};
use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use axum_extra::response::ErasedJson;
use colored::Colorize;
use reqwest::{StatusCode};
use std::{error::Error, fmt};
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum SlashstepServerError {
    #[error("Please set a value for the environment variable \"{0}\".")]
    EnvironmentVariableNotSet(String),

    #[error(transparent)]
    ResourceError(#[from] ResourceError),

    #[error(transparent)]
    PostgresError(#[from] postgres::Error),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error(transparent)]
    DeadpoolBuildError(#[from] deadpool_postgres::BuildError),

    #[error(transparent)]
    DeadpoolPoolError(#[from] deadpool_postgres::PoolError),

    #[error(transparent)]
    RedisCreatePoolError(#[from] deadpool_redis::CreatePoolError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    LocalIPAddressError(#[from] local_ip_address::Error),

    #[error(transparent)]
    OpenSearchError(#[from] opensearch::Error),

    #[error(transparent)]
    OpenSearchTransportBuilderBuildError(#[from] opensearch::http::transport::BuildError),

    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),

    #[error(transparent)]
    RcgenError(#[from] rcgen::Error),

    #[error(transparent)]
    YAMLSerdeError(#[from] yaml_serde::Error),
}

pub async fn create_database_pool(slashstep_server_postgresql_config: Option<&SlashstepServerPostgreSQLConfig>) -> Result<deadpool_postgres::Pool, SlashstepServerError> {
    let slashstep_server_postgresql_config = slashstep_server_postgresql_config
        .cloned()
        .unwrap_or_default();
    let host = slashstep_server_postgresql_config
        .host
        .clone()
        .unwrap_or("localhost".to_string());
    let port = slashstep_server_postgresql_config
        .port
        .clone()
        .unwrap_or(5432);
    let username = slashstep_server_postgresql_config
        .username
        .clone()
        .unwrap_or("slashstep_server".to_string());
    let database_name = slashstep_server_postgresql_config.database_name.clone().unwrap_or("postgres".to_string());
    let password_path = slashstep_server_postgresql_config.password_file_path.clone().unwrap_or("./secrets/postgresql-password.txt".to_string());

    trace!(
        "Attempting to read PostgreSQL password from file at {}...",
        &password_path
    );
    let password = match std::fs::read_to_string(&password_path) {
        Ok(password) => password,
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => panic!(
                "The PostgreSQL password file was not found at {}. Please make sure it exists and is readable by the application.",
                &password_path
            ),

            _ => panic!(
                "An error occurred while trying to read the PostgreSQL password file: {}",
                error
            ),
        },
    };

    let mut postgres_config = tokio_postgres::Config::new();
    postgres_config.host(host);
    postgres_config.port(port);
    postgres_config.user(username);
    postgres_config.dbname(database_name);
    postgres_config.password(password);
    let manager_config = deadpool_postgres::ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Fast,
    };
    let manager = deadpool_postgres::Manager::from_config(postgres_config, NoTls, manager_config);

    let maximum_postgres_connection_count = slashstep_server_postgresql_config.maximum_connection_count.unwrap_or(DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT.to_usize().expect("Failed to convert default maximum PostgreSQL connection count to usize."));

    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(maximum_postgres_connection_count)
        .build()?;
    Ok(pool)
}

pub async fn create_redis_pool(slashstep_server_redis_config: Option<&SlashstepServerRedisConfig>) -> Result<deadpool_redis::Pool, SlashstepServerError> {

    let slashstep_server_redis_config = slashstep_server_redis_config
        .cloned()
        .unwrap_or_default();
    let redis_url = slashstep_server_redis_config.url.clone().unwrap_or("redis://localhost:6379".to_string());
    let redis_config = deadpool_redis::Config::from_url(redis_url);
    let redis_pool = redis_config.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    Ok(redis_pool)
}

pub async fn initialize_required_tables(
    database_pool: &deadpool_postgres::Pool,
) -> Result<(), SlashstepServerError> {
    trace!("Initializing required tables...");

    let create_general_types_query = include_str!("./queries/create_general_types.sql");
    database_pool
        .get()
        .await?
        .execute(create_general_types_query, &[])
        .await?;

    // Because the access_policies table depends on other tables, we need to initialize them in a specific order.
    HTTPTransaction::initialize_resource_table(database_pool).await?;
    ServerLogEntry::initialize_resource_table(database_pool).await?;
    Workspace::initialize_resource_table(database_pool).await?;
    User::initialize_resource_table(database_pool).await?;
    PasswordResetAuthorization::initialize_resource_table(database_pool).await?;
    Session::initialize_resource_table(database_pool).await?;
    SessionCredential::initialize_resource_table(database_pool).await?;
    Group::initialize_resource_table(database_pool).await?;
    App::initialize_resource_table(database_pool).await?;
    Project::initialize_resource_table(database_pool).await?;
    Status::initialize_resource_table(database_pool).await?;
    Webhook::initialize_resource_table(database_pool).await?;
    ItemTypeIcon::initialize_resource_table(database_pool).await?;
    Iteration::initialize_resource_table(database_pool).await?;
    ItemType::initialize_resource_table(database_pool).await?;
    View::initialize_resource_table(database_pool).await?;
    Role::initialize_resource_table(database_pool).await?;
    Membership::initialize_resource_table(database_pool).await?;
    MembershipInvitation::initialize_resource_table(database_pool).await?;
    Item::initialize_resource_table(database_pool).await?;
    ItemConnectionType::initialize_resource_table(database_pool).await?;
    ItemConnection::initialize_resource_table(database_pool).await?;
    Action::initialize_resource_table(database_pool).await?;
    AppCredential::initialize_resource_table(database_pool).await?;
    Milestone::initialize_resource_table(database_pool).await?;
    ActionLogEntry::initialize_resource_table(database_pool).await?;
    OAuthAuthorization::initialize_resource_table(database_pool).await?;
    AppAuthorization::initialize_resource_table(database_pool).await?;
    AppAuthorizationCredential::initialize_resource_table(database_pool).await?;
    Field::initialize_resource_table(database_pool).await?;
    FieldChoice::initialize_resource_table(database_pool).await?;
    FieldValue::initialize_resource_table(database_pool).await?;
    ViewField::initialize_resource_table(database_pool).await?;
    Configuration::initialize_resource_table(database_pool).await?;
    DelegationPolicy::initialize_resource_table(database_pool).await?;
    AccessPolicy::initialize_resource_table(database_pool).await?;

    let database_client = database_pool.get().await?;
    let query = include_str!("./queries/items/initialize_searchable_items_view.sql");
    database_client.execute(query, &[]).await?;

    debug!("Successfully initialized all tables.");

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HTTPError {
    GoneError(Option<String>),
    Forbidden(Option<String>),
    NotFoundError(Option<String>),
    ConflictError(Option<String>),
    BadRequest(Option<String>),
    UnsupportedMediaType(Option<String>),
    MethodNotAllowed(Option<String>),
    NotImplementedError(Option<String>),
    InternalServerError(Option<String>),
    Unauthorized(Option<String>),
    UnprocessableEntity(Option<String>),
    PayloadTooLarge(Option<String>),
    TooManyRequests(Option<String>),
}

impl HTTPError {
    fn log(&self) {
        match self {
            HTTPError::InternalServerError(_) => {
                error!("{}", self.to_string());
            }
            _ => {
                warn!("{}", self.to_string());
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HTTPErrorBody {
    pub message: String,
}

impl fmt::Display for HTTPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HTTPError::NotFoundError(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Not found.".to_string())
            ),
            HTTPError::ConflictError(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Conflict.".to_string())
            ),
            HTTPError::Forbidden(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Forbidden.".to_string())
            ),
            HTTPError::GoneError(message) => {
                write!(f, "{}", message.to_owned().unwrap_or("Gone.".to_string()))
            }
            HTTPError::BadRequest(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Bad request.".to_string())
            ),
            HTTPError::MethodNotAllowed(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Method not allowed.".to_string())
            ),
            HTTPError::NotImplementedError(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Not implemented.".to_string())
            ),
            HTTPError::InternalServerError(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Internal server error.".to_string())
            ),
            HTTPError::Unauthorized(message) => write!(
                f,
                "{}",
                message.to_owned().unwrap_or("Unauthorized.".to_string())
            ),
            HTTPError::UnsupportedMediaType(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Unsupported media type.".to_string())
            ),
            HTTPError::UnprocessableEntity(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Unprocessable entity.".to_string())
            ),
            HTTPError::PayloadTooLarge(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Payload too large.".to_string())
            ),
            HTTPError::TooManyRequests(message) => write!(
                f,
                "{}",
                message
                    .to_owned()
                    .unwrap_or("Too many requests.".to_string())
            ),
        }
    }
}

impl IntoResponse for HTTPError {
    fn into_response(self) -> Response {
        let (status_code, error_message) = match self {
            HTTPError::GoneError(message) => {
                (StatusCode::GONE, message.unwrap_or("Gone.".to_string()))
            }

            HTTPError::NotFoundError(message) => (
                StatusCode::NOT_FOUND,
                message.unwrap_or("Not found.".to_string()),
            ),

            HTTPError::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                message.unwrap_or("Forbidden.".to_string()),
            ),

            HTTPError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                message.unwrap_or("Bad request.".to_string()),
            ),

            HTTPError::ConflictError(message) => (
                StatusCode::CONFLICT,
                message.unwrap_or("Conflict.".to_string()),
            ),

            HTTPError::Unauthorized(message) => (
                StatusCode::UNAUTHORIZED,
                message.unwrap_or("Unauthorized.".to_string()),
            ),

            HTTPError::UnsupportedMediaType(message) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                message.unwrap_or("Unsupported media type.".to_string()),
            ),

            HTTPError::MethodNotAllowed(message) => (
                StatusCode::METHOD_NOT_ALLOWED,
                message.unwrap_or("Method not allowed.".to_string()),
            ),

            HTTPError::NotImplementedError(message) => (
                StatusCode::NOT_IMPLEMENTED,
                message.unwrap_or("Not implemented.".to_string()),
            ),

            HTTPError::UnprocessableEntity(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                message.unwrap_or("Unprocessable entity.".to_string()),
            ),

            HTTPError::PayloadTooLarge(message) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                message.unwrap_or("Payload too large.".to_string()),
            ),

            HTTPError::TooManyRequests(message) => (
                StatusCode::TOO_MANY_REQUESTS,
                message.unwrap_or("Too many requests.".to_string()),
            ),

            HTTPError::InternalServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something bad happened on our side. Please try again later.".to_string(),
            ),
        };

        (
            status_code,
            ErasedJson::pretty(HTTPErrorBody {
                message: error_message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub database_pool: deadpool_postgres::Pool,
    pub redis_pool: deadpool_redis::Pool,
    pub opensearch_client: OpenSearch
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TLSMode {
    UseDemoCertificate,
    UseCustomCertificate,
    DisableTLS
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerPostgreSQLConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database_name: Option<String>,
    pub username: Option<String>,
    pub password_file_path: Option<String>,
    pub maximum_connection_count: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerNetworkConfig {
    pub port: Option<u16>,
    pub tls_mode: Option<TLSMode>,
    pub demo_certificates_directory_path: Option<String>
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerJWTConfig {
    pub public_key_path: Option<String>,
    pub private_key_path: Option<String>
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerOpenSearchConfig {
    pub url: Option<String>,
    pub client_certificate_path: Option<String>,
    pub client_key_path: Option<String>,
    pub root_ca_path: Option<String>
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerRedisConfig {
    pub url: Option<String>
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerSetupConfig {
    pub admin_username: Option<String>,
    pub admin_password_file_path: Option<String>
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SlashstepServerConfig {
    pub postgresql: Option<SlashstepServerPostgreSQLConfig>,
    pub network: Option<SlashstepServerNetworkConfig>,
    pub jwt: Option<SlashstepServerJWTConfig>,
    pub opensearch: Option<SlashstepServerOpenSearchConfig>,
    pub redis: Option<SlashstepServerRedisConfig>,
    pub setup: Option<SlashstepServerSetupConfig>
}

pub fn create_opensearch_client(slashstep_server_opensearch_config: Option<&SlashstepServerOpenSearchConfig>) -> Result<OpenSearch, SlashstepServerError> {
    trace!("Creating OpenSearch client...");
    let slashstep_server_opensearch_config = slashstep_server_opensearch_config
        .cloned()
        .unwrap_or_default();
    let opensearch_url_string = slashstep_server_opensearch_config.url.clone().unwrap_or("https://localhost:9200".to_string());
    let opensearch_url = Url::parse(&opensearch_url_string)?;
    let opensearch_client_certificate_path = slashstep_server_opensearch_config.client_certificate_path.clone().unwrap_or("./secrets/opensearch-client-certificate.pem".to_string());
    let opensearch_client_key_path = slashstep_server_opensearch_config.client_key_path.clone().unwrap_or("./secrets/opensearch-client-key.pem".to_string());
    let opensearch_root_ca_path = slashstep_server_opensearch_config.root_ca_path.clone().unwrap_or("./secrets/opensearch-root-ca.pem".to_string());
    let mut opensearch_credential_bytes = std::fs::read(opensearch_client_certificate_path)?;
    opensearch_credential_bytes.extend(std::fs::read(opensearch_client_key_path)?);
    let root_ca_bytes = std::fs::read(opensearch_root_ca_path)?;
    let opensearch_client_certificate = opensearch::auth::ClientCertificate::Pem(opensearch_credential_bytes);
    let opensearch_credentials = opensearch::auth::Credentials::Certificate(opensearch_client_certificate);
    let opensearch_connection_pool = SingleNodeConnectionPool::new(opensearch_url);
    let opensearch_transport = opensearch::http::transport::TransportBuilder::new(opensearch_connection_pool)
        .auth(opensearch_credentials)
        .cert_validation(opensearch::cert::CertificateValidation::Full(
            opensearch::cert::Certificate::from_pem(&root_ca_bytes)?
        ))
        .build()?;
    let opensearch_client = OpenSearch::new(opensearch_transport); 
    Ok(opensearch_client)
}

#[derive(Debug)]
pub struct OpenSearchLayer {
    pub sender: mpsc::Sender<StructuredLogEntry>
}

#[derive(Debug, Serialize)]
pub struct StructuredLogEntry {
    /// The message of the server log entry.
    pub message: String,

    /// The HTTP transaction ID of the server log entry, if applicable.
    pub http_transaction_id: Option<Uuid>,

    /// The level of the server log entry.
    pub level: String,
}

#[derive(Debug, Default)]
pub struct OpenSearchLogVisitor {
    pub message: String,
    pub http_transaction_id: Option<Uuid>
}

impl<S: Subscriber> tracing_subscriber::layer::Layer<S> for OpenSearchLayer {
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        
        let mut visitor = OpenSearchLogVisitor::default();
        event.record(&mut visitor);

        let log_entry = StructuredLogEntry {
            message: visitor.message,
            http_transaction_id: visitor.http_transaction_id,
            level: event.metadata().level().to_string()
        };

        let _ = self.sender.try_send(log_entry);
        
    }
}

impl tracing::field::Visit for OpenSearchLogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "http_transaction_id" {
            self.http_transaction_id = Uuid::parse_str(value).and_then(|value| Ok(Some(value))).unwrap_or(None);
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }
}

pub async fn run_opensearch_log_worker(mut receiver: mpsc::Receiver<StructuredLogEntry>, opensearch_client: OpenSearch) {
    while let Some(log_entry) = receiver.recv().await {
        let result = opensearch_client.index(opensearch::IndexParts::Index("server_log_entries"))
            .body(serde_json::json!(log_entry))
            .send()
            .await;

        match result {
            Ok(response) => {
                if !response.status_code().is_success() {
                    eprintln!("Failed to send log entry to OpenSearch. Status code: {}. Response body: {:?}", response.status_code(), response.text().await.unwrap_or("Could not read response body.".to_string()));
                }
            },
            Err(error) => {
                eprintln!("Failed to send log entry to OpenSearch: {:?}", error.source());
            }
        }
    }
}

pub async fn get_json_web_token_public_key() -> Result<String, ResourceError> {
    let jwt_public_key_path = std::env::var("SLASHSTEP_JWT_PUBLIC_KEY_PATH")?;
    let jwt_public_key = std::fs::read_to_string(&jwt_public_key_path)?;

    Ok(jwt_public_key)
}

pub async fn get_json_web_token_private_key() -> Result<String, ResourceError> {
    let jwt_private_key_path = std::env::var("SLASHSTEP_JWT_PRIVATE_KEY_PATH")?;
    let jwt_private_key = std::fs::read_to_string(&jwt_private_key_path)?;

    Ok(jwt_private_key)
}

pub fn handle_pool_error(error: deadpool_postgres::PoolError) -> Response<Body> {
    error!("Failed to get database connection: {}", error);
    let http_error = HTTPError::InternalServerError(Some(error.to_string()));
    http_error.into_response()
}

pub fn get_environment_variable(variable_name: &str) -> Result<String, SlashstepServerError> {
    trace!("Getting environment variable {}...", variable_name);
    let variable_value = match std::env::var(variable_name) {
        Ok(variable_value) => variable_value,

        Err(_) => {
            return Err(SlashstepServerError::EnvironmentVariableNotSet(
                variable_name.to_string(),
            ));
        }
    };

    Ok(variable_value)
}

pub fn import_env_file() {
    if dotenvy::dotenv().is_ok() {
        debug!("Successfully imported environment variables from .env file.");
    }
}

pub async fn setup_admin_user_if_necessary(
    slashstep_server_setup_config: Option<&SlashstepServerSetupConfig>,
    postgres_pool: &deadpool_postgres::Pool,
) -> Result<(), SlashstepServerError> {
    let postgres_pool = postgres_pool.clone();
    let should_setup_admin_user_configuration =
        Configuration::get_by_name("users.shouldSetupAdminUser", &postgres_pool).await?;
    if !should_setup_admin_user_configuration
        .boolean_value
        .unwrap_or(true)
    {
        return Ok(());
    }

    let slashstep_server_setup_config = slashstep_server_setup_config
        .cloned()
        .unwrap_or_default();
    let mut slashstep_admin_username = slashstep_server_setup_config.admin_username.clone().unwrap_or("".to_string());
    let mut slashstep_admin_password =
        match &slashstep_server_setup_config.admin_password_file_path {
            Some(slashstep_admin_password_file_path) => {
                std::fs::read_to_string(slashstep_admin_password_file_path)?
            },

            None => "".to_string()
        };

    println!(
        "\nIt looks like this is your first time running the Slashstep Server, so let's set up an admin user."
    );
    println!(
        "If you can't use the console, please set SLASHSTEP_ADMIN_USERNAME and SLASHSTEP_ADMIN_PASSWORD_FILE_PATH environment variables and restart the server. After creating the admin user, you can remove those environment variables if you want."
    );
    println!("\nWhat username should the admin user have?");
    loop {
        if slashstep_admin_username.is_empty() {
            while slashstep_admin_username.is_empty() {
                std::io::stdin().read_line(&mut slashstep_admin_username)?;

                if slashstep_admin_username.trim().is_empty() {
                    println!(
                        "{}",
                        "Username cannot be empty. Please enter a valid username.".red()
                    );
                    slashstep_admin_username = "".to_string();
                }
            }
        } else {
            println!(
                "{}",
                "(pre-filled from SLASHSTEP_ADMIN_USERNAME environment variable)".dimmed()
            );
        }

        slashstep_admin_username = slashstep_admin_username.trim().to_string();

        println!("What password should the admin user have?");
        if slashstep_admin_password.is_empty() {
            while slashstep_admin_password.is_empty() {
                slashstep_admin_password = match rpassword::read_password() {
                    Ok(password) => {
                        if password.trim().is_empty() {
                            println!(
                                "{}",
                                "Password cannot be empty. Please enter a valid password.".red()
                            );
                            continue;
                        } else {
                            password.trim().to_string()
                        }
                    }
                    Err(error) => panic!(
                        "An error occurred while trying to read the password: {}",
                        error
                    ),
                };

                println!("Please re-enter the password to confirm.");
                let confirmation_password = match rpassword::read_password() {
                    Ok(confirmation_password) => confirmation_password.trim().to_string(),
                    Err(error) => panic!(
                        "An error occurred while trying to read the password confirmation: {}",
                        error
                    ),
                };

                if slashstep_admin_password != confirmation_password {
                    println!("{}", "The passwords do not match.".red());
                    println!("Let's try again. What password should the admin user have?");
                    slashstep_admin_password = "".to_string();
                }
            }
        } else {
            println!("{}", "(pre-filled from file set in the SLASHSTEP_ADMIN_PASSWORD_FILE_PATH environment variable)".dimmed());
        }

        println!("Setting up admin user...");
        let admin_user = match User::create(
            &InitialUserProperties {
                username: Some(slashstep_admin_username.clone()),
                display_name: Some(slashstep_admin_username.clone()),
                hashed_password: Some(User::hash_password(&slashstep_admin_password)?),
                ..Default::default()
            },
            &postgres_pool,
        )
        .await
        {
            Ok(admin_user) => admin_user,

            Err(error) => match error {
                ResourceError::ConflictError(_) => {
                    println!("{}", "A user with that username already exists. Please choose a different username.".red());
                    slashstep_admin_username = "".to_string();
                    slashstep_admin_password = "".to_string();
                    continue;
                }

                error => return Err(SlashstepServerError::ResourceError(error)),
            },
        };

        let server_admin_role = Role::get_by_predefined_role_type(
            &RoleParentResourceType::Server,
            None,
            &PredefinedRoleType::ServerAdmins,
            &postgres_pool,
        )
        .await?;

        Membership::create(
            &InitialMembershipProperties {
                parent_resource_type: MembershipParentResourceType::Role,
                parent_role_id: Some(server_admin_role.id),
                principal_type: MembershipPrincipalType::User,
                principal_user_id: Some(admin_user.id),
                ..Default::default()
            },
            &postgres_pool,
        )
        .await?;

        println!("{}", "All done! The admin user has been set up, and you can use it to sign in using a Slashstep client.".blue());
        println!("Thanks for using Slashstep Server. ✌️\n");

        should_setup_admin_user_configuration
            .update(
                &EditableConfigurationProperties {
                    boolean_value: Some(false),
                    ..Default::default()
                },
                &postgres_pool,
            )
            .await?;

        break;
    }

    Ok(())
}
