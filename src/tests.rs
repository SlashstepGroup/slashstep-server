use chrono::{Duration, Utc};
use deadpool_postgres::tokio_postgres;
use ed25519_dalek::{SigningKey, ed25519::signature::rand_core::OsRng, pkcs8::{EncodePublicKey, spki::der::pem::LineEnding}};
use local_ip_address::local_ip;
use postgres::NoTls;
use testcontainers_modules::{testcontainers::runners::AsyncRunner};
use testcontainers::{ImageExt};
use uuid::Uuid;
use crate::{DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT, SlashstepServerError, import_env_file, resources::{ResourceError, access_policy::{AccessPolicy, ActionPermissionLevel, InitialAccessPolicyProperties}, action::{Action, ActionParentResourceType, InitialActionProperties}, action_log_entry::{ActionLogEntry, InitialActionLogEntryProperties}, app::{App, AppClientType, AppParentResourceType, InitialAppProperties}, app_authorization::{AppAuthorization, InitialAppAuthorizationProperties}, app_authorization_credential::{AppAuthorizationCredential, InitialAppAuthorizationCredentialProperties}, app_credential::{AppCredential, InitialAppCredentialProperties}, configuration::{Configuration, ConfigurationValueType, InitialConfigurationProperties}, delegation_policy::{DelegationPolicy, InitialDelegationPolicyProperties}, field::{Field, FieldParentResourceType, FieldValueType, InitialFieldProperties}, field_choice::{FieldChoice, FieldChoiceType, InitialFieldChoiceProperties}, field_value::{FieldValue, FieldValueParentResourceType, InitialFieldValueProperties}, group::{Group, GroupParentResourceType, InitialGroupProperties}, http_transaction::{HTTPTransaction, InitialHTTPTransactionProperties}, item::{InitialItemProperties, Item}, item_connection::{InitialItemConnectionProperties, ItemConnection}, item_connection_type::{InitialItemConnectionTypeProperties, ItemConnectionType, ItemConnectionTypeParentResourceType}, membership::{InitialMembershipProperties, Membership, MembershipParentResourceType}, milestone::{InitialMilestoneProperties, Milestone}, oauth_authorization::{InitialOAuthAuthorizationProperties, OAuthAuthorization}, project::{InitialProjectProperties, Project}, role::{InitialRoleProperties, Role}, server_log_entry::{InitialServerLogEntryProperties, ServerLogEntry, ServerLogEntryLevel}, session::{InitialSessionProperties, Session}, user::{InitialUserProperties, User}, view::{InitialViewProperties, View, ViewParentResourceType}, workspace::{InitialWorkspaceProperties, Workspace}}, utilities::resource_hierarchy::ResourceHierarchyError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TestSlashstepServerError {

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
  IOError(#[from] std::io::Error),

  #[error(transparent)]
  LocalIPAddressError(#[from] local_ip_address::Error),

  #[error(transparent)]
  ResourceHierarchyError(#[from] ResourceHierarchyError),

  #[error(transparent)]
  TestcontainersError(#[from] testcontainers::TestcontainersError),

  #[error(transparent)]
  PKCS8Error(#[from] ed25519_dalek::pkcs8::Error),

  #[error(transparent)]
  SPKIError(#[from] ed25519_dalek::pkcs8::spki::Error),

  #[error(transparent)]
  SlashstepServerError(#[from] SlashstepServerError),

  #[error(transparent)]
  AnyhowError(#[from] anyhow::Error),

  #[error(transparent)]
  JsonWebTokenError(#[from] jsonwebtoken::errors::Error)

}

pub struct TestEnvironment {

  pub database_pool: deadpool_postgres::Pool,

  // This is required to prevent the compiler from complaining about unused fields.
  // We need a wrapper struct to fix lifetime issues, but we don't need to use the container for any test right now.
  #[allow(dead_code)]
  pub postgres_container: testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>

}

impl TestEnvironment {

  pub async fn new() -> Result<Self, TestSlashstepServerError> {

    import_env_file();
    
    let postgres_container = testcontainers_modules::postgres::Postgres::default()
      .with_tag("18")
      .start()
      .await?;
    let postgres_host = postgres_container.get_host().await?;
    let postgres_port = postgres_container.get_host_port_ipv4(5432).await?;

    let mut postgres_config = tokio_postgres::Config::new();
    postgres_config.host(postgres_host.to_string());
    postgres_config.port(postgres_port);
    postgres_config.user("postgres");
    postgres_config.password("postgres");
    let manager_config = deadpool_postgres::ManagerConfig {
      recycling_method: deadpool_postgres::RecyclingMethod::Fast
    };
    let manager = deadpool_postgres::Manager::from_config(postgres_config, NoTls, manager_config);

    let database_pool = deadpool_postgres::Pool::builder(manager).max_size(DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT as usize).build()?;

    let environment = TestEnvironment {
      database_pool: database_pool,
      postgres_container: postgres_container
    };

    return Ok(environment);

  }

  pub async fn create_random_app(&self) -> Result<App, TestSlashstepServerError> {

    let app_properties = InitialAppProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      client_type: AppClientType::Public,
      client_secret_hash: Some(Uuid::now_v7().to_string()),
      parent_resource_type: AppParentResourceType::Server,
      parent_workspace_id: None,
      parent_user_id: None
    };

    let app = App::create(&app_properties, &self.database_pool).await?;

    return Ok(app);

  }

  pub async fn create_random_oauth_authorization(&self, app_id: Option<&Uuid>, code_challenge: Option<&str>) -> Result<OAuthAuthorization, TestSlashstepServerError> {

    let oauth_authorization_properties = InitialOAuthAuthorizationProperties {
      app_id: app_id.copied().unwrap_or(self.create_random_app().await?.id),
      authorizing_user_id: self.create_random_user().await?.id,
      code_challenge: code_challenge.map(|code_challenge| code_challenge.to_string()),
      code_challenge_method: code_challenge.and(Some("S256".to_string())),
      redirect_uri: None,
      scope: Uuid::now_v7().to_string(),
      usage_date: None,
      state: None
    };

    let oauth_authorization = OAuthAuthorization::create(&oauth_authorization_properties, &self.database_pool).await?;

    return Ok(oauth_authorization);

  }
  
  pub async fn create_random_action(&self, parent_app_id: Option<&Uuid>) -> Result<Action, TestSlashstepServerError> {

    let action_properties = InitialActionProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      parent_app_id: parent_app_id.copied(),
      parent_resource_type: if parent_app_id.is_some() { ActionParentResourceType::App } else { ActionParentResourceType::Server }
    };

    let action = Action::create(&action_properties, &self.database_pool).await?;

    return Ok(action);

  }

  pub async fn create_random_app_authorization(&self, app_id: Option<&Uuid>) -> Result<AppAuthorization, TestSlashstepServerError> {

    // Create a random app.
    let app_id = app_id.copied().unwrap_or(self.create_random_app().await?.id);
    let app_authorization_properties = InitialAppAuthorizationProperties {
      app_id,
      ..Default::default()
    };

    let app_authorization = AppAuthorization::create(&app_authorization_properties, &self.database_pool).await?;

    return Ok(app_authorization);

  }

  pub async fn create_random_app_authorization_credential(&self, app_authorization_id: Option<&Uuid>) -> Result<AppAuthorizationCredential, TestSlashstepServerError> {

    // Create a random app.
    let app_authorization_id = app_authorization_id.copied().unwrap_or(self.create_random_app_authorization(None).await?.id);
    let app_authorization_properties = InitialAppAuthorizationCredentialProperties {
      app_authorization_id,
      access_token_expiration_date: Utc::now() + Duration::days(1),
      refresh_token_expiration_date: Utc::now() + Duration::days(30),
      refreshed_app_authorization_credential_id: None
    };

    let app_authorization_credential = AppAuthorizationCredential::create(&app_authorization_properties, &self.database_pool).await?;

    return Ok(app_authorization_credential);

  }

  pub async fn create_random_app_credential(&self, app_id: Option<&Uuid>) -> Result<AppCredential, TestSlashstepServerError> {

    // Create a random app.
    let app_id = app_id.copied().unwrap_or(self.create_random_app().await?.id);

    // Create a public key.
    let mut os_rng = OsRng;
    let signing_key = SigningKey::generate(&mut os_rng);
    let public_key = signing_key.verifying_key().to_public_key_pem(LineEnding::LF)?;
    let local_ip = local_ip()?;
    let app_credential_properties = InitialAppCredentialProperties {
      app_id: app_id,
      description: Some(Uuid::now_v7().to_string()),
      expiration_date: Some(Utc::now() + Duration::days(30)),
      creation_ip_address: local_ip,
      public_key: public_key.clone()
    };

    let app_credential = AppCredential::create(&app_credential_properties, &self.database_pool).await?;

    return Ok(app_credential);

  }

  pub async fn create_random_action_log_entry(&self) -> Result<ActionLogEntry, TestSlashstepServerError> {

    let action = self.create_random_action(None).await?;
    let user = self.create_random_user().await?;

    let action_log_entry_properties = InitialActionLogEntryProperties {
      action_id: action.id,
      actor_user_id: Some(user.id),
      ..Default::default()
    };

    let action_log_entry = ActionLogEntry::create(&action_log_entry_properties, &self.database_pool).await?;

    return Ok(action_log_entry);

  }

  pub async fn create_random_configuration(&self) -> Result<Configuration, TestSlashstepServerError> {

    let configuration_properties = InitialConfigurationProperties {
      name: Uuid::now_v7().to_string(),
      value_type: ConfigurationValueType::Text,
      ..Default::default()
    };

    let configuration = Configuration::create(&configuration_properties, &self.database_pool).await?;

    return Ok(configuration);

  }

  pub async fn create_random_delegation_policy(&self) -> Result<DelegationPolicy, TestSlashstepServerError> {

    let action = self.create_random_action(None).await?;
    let user = self.create_random_user().await?;

    let delegation_policy_properties = InitialDelegationPolicyProperties {
      action_id: action.id,
      maximum_permission_level: ActionPermissionLevel::User,
      delegate_app_authorization_id: self.create_random_app_authorization(None).await?.id,
      principal_user_id: user.id,
      ..Default::default()
    };

    let delegation_policy = DelegationPolicy::create(&delegation_policy_properties, &self.database_pool).await?;

    return Ok(delegation_policy);

  }

  pub async fn create_random_field(&self) -> Result<Field, TestSlashstepServerError> {

    let parent_workspace = self.create_random_workspace().await?;
    let field_properties = InitialFieldProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Uuid::now_v7().to_string(),
      is_required: true,
      field_value_type: FieldValueType::Text,
      parent_resource_type: FieldParentResourceType::Workspace,
      parent_workspace_id: Some(parent_workspace.id),
      ..Default::default()
    };

    let field = Field::create(&field_properties, &self.database_pool).await?;

    return Ok(field);

  }

  pub async fn create_random_field_choice(&self, field_id: Option<&Uuid>) -> Result<FieldChoice, TestSlashstepServerError> {

    let field_choice_properties = InitialFieldChoiceProperties {
      field_id: field_id.copied().unwrap_or(self.create_random_field().await?.id),
      description: Some(Uuid::now_v7().to_string()),
      value_type: FieldChoiceType::Text,
      text_value: Some(Uuid::now_v7().to_string()),
      ..Default::default()
    };

    let field_choice = FieldChoice::create(&field_choice_properties, &self.database_pool).await?;

    return Ok(field_choice);

  }

  pub async fn create_random_field_value(&self) -> Result<FieldValue, TestSlashstepServerError> {

    let field = self.create_random_field().await?;
    let field_choice_properties = InitialFieldValueProperties {
      field_id: field.id,
      parent_resource_type: FieldValueParentResourceType::Field,
      parent_field_id: Some(field.id),
      value_type: FieldValueType::Text,
      text_value: Some(Uuid::now_v7().to_string()),
      ..Default::default()
    };

    let field_choice = FieldValue::create(&field_choice_properties, &self.database_pool).await?;

    return Ok(field_choice);

  }

  pub async fn create_random_group(&self) -> Result<Group, TestSlashstepServerError> {

    let group_properties = InitialGroupProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string())
    };

    let group = Group::create(&group_properties, &self.database_pool).await?;

    return Ok(group);

  }

  pub async fn create_random_http_transaction(&self) -> Result<HTTPTransaction, TestSlashstepServerError> {

    let http_transaction_properties = InitialHTTPTransactionProperties {
      method: "GET".to_string(),
      url: Uuid::now_v7().to_string(),
      ip_address: local_ip()?,
      headers: Uuid::now_v7().to_string(),
      status_code: Some(200),
      expiration_timestamp: Some(Utc::now() + Duration::days(30)),
    };

    let http_transaction = HTTPTransaction::create(&http_transaction_properties, &self.database_pool).await?;

    return Ok(http_transaction);

  }

  pub async fn create_random_item(&self) -> Result<Item, TestSlashstepServerError> {

    let item_properties = InitialItemProperties {
      summary: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      project_id: self.create_random_project().await?.id,
      ..Default::default()
    };

    let item = Item::create(&item_properties, &self.database_pool).await?;

    return Ok(item);

  }

  pub async fn create_random_item_connection(&self) -> Result<ItemConnection, TestSlashstepServerError> {

    let item_connection_type = self.create_random_item_connection_type().await?;
    let inward_item = self.create_random_item().await?;
    let outward_item = self.create_random_item().await?;

    let item_connection_properties = InitialItemConnectionProperties {
      item_connection_type_id: item_connection_type.id,
      inward_item_id: inward_item.id,
      outward_item_id: outward_item.id
    };

    let item_connection = ItemConnection::create(&item_connection_properties, &self.database_pool).await?;

    return Ok(item_connection);

  }

  pub async fn create_random_item_connection_type(&self) -> Result<ItemConnectionType, TestSlashstepServerError> {

    let workspace = self.create_random_workspace().await?;
    let item_connection_type_properties = InitialItemConnectionTypeProperties {
      display_name: Uuid::now_v7().to_string(),
      inward_description: Uuid::now_v7().to_string(),
      outward_description: Uuid::now_v7().to_string(),
      parent_resource_type: ItemConnectionTypeParentResourceType::Workspace,
      parent_workspace_id: Some(workspace.id),
      ..Default::default()
    };

    let item_connection_type = ItemConnectionType::create(&item_connection_type_properties, &self.database_pool).await?;

    return Ok(item_connection_type);

  }

  pub async fn create_random_membership(&self) -> Result<Membership, TestSlashstepServerError> {

    let membership_properties = InitialMembershipProperties {
      parent_resource_type: MembershipParentResourceType::Group,
      parent_group_id: Some(self.create_random_group().await?.id),
      ..Default::default()
    };

    let membership = Membership::create(&membership_properties, &self.database_pool).await?;

    return Ok(membership);

  }

  pub async fn create_random_milestone(&self) -> Result<Milestone, TestSlashstepServerError> {

    let project = self.create_random_project().await?;
    let milestone_properties = InitialMilestoneProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      parent_resource_type: crate::resources::milestone::MilestoneParentResourceType::Project,
      parent_project_id: Some(project.id),
      ..Default::default()
    };

    let milestone = Milestone::create(&milestone_properties, &self.database_pool).await?;

    return Ok(milestone);

  }

  pub async fn create_random_project(&self) -> Result<Project, TestSlashstepServerError> {

    let project_properties = InitialProjectProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      key: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      start_date: Some(Utc::now()),
      end_date: Some(Utc::now()),
      workspace_id: self.create_random_workspace().await?.id
    };

    let project = Project::create(&project_properties, &self.database_pool).await?;

    return Ok(project);

  }

  pub async fn create_random_role(&self) -> Result<Role, TestSlashstepServerError> {

    let role_properties = InitialRoleProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string()),
      parent_resource_type: crate::resources::role::RoleParentResourceType::Server,
      ..Default::default()
    };

    let role = Role::create(&role_properties, &self.database_pool).await?;

    return Ok(role);

  }

  pub async fn create_random_server_log_entry(&self) -> Result<ServerLogEntry, TestSlashstepServerError> {

    let server_log_entry_properties = InitialServerLogEntryProperties {
      message: Uuid::now_v7().to_string(),
      http_transaction_id: None,
      level: ServerLogEntryLevel::Info
    };

    let server_log_entry = ServerLogEntry::create(&server_log_entry_properties, &self.database_pool).await?;

    return Ok(server_log_entry);

  }

  pub async fn create_random_session(&self, user_id: Option<&Uuid>) -> Result<Session, TestSlashstepServerError> {

    let local_ip = local_ip()?;
    let user_id = user_id.copied().unwrap_or(self.create_random_user().await?.id);
    let session_properties = InitialSessionProperties {
      user_id: user_id,
      expiration_date: (Utc::now() + Duration::days(30)),
      creation_ip_address: local_ip
    };

    let session = Session::create(&session_properties, &self.database_pool).await?;

    return Ok(session);

  }

  pub async fn create_random_user(&self) -> Result<User, TestSlashstepServerError> {

    let user_properties = InitialUserProperties {
      username: Some(Uuid::now_v7().to_string()),
      display_name: Some(Uuid::now_v7().to_string()),
      hashed_password: Some(Uuid::now_v7().to_string()),
      is_anonymous: false,
      ip_address: None
    };

    let user = User::create(&user_properties, &self.database_pool).await?;

    return Ok(user);

  }

  pub async fn create_random_view(&self) -> Result<View, TestSlashstepServerError> {

    let project = self.create_random_project().await?;
    let view_properties = InitialViewProperties {
      parent_resource_type: ViewParentResourceType::Project,
      parent_project_id: Some(project.id),
      ..Default::default()
    };

    let view = View::create(&view_properties, &self.database_pool).await?;

    return Ok(view);

  }

  pub async fn create_random_access_policy(&self) -> Result<AccessPolicy, TestSlashstepServerError> {

    let action = self.create_random_action(None).await?;
    let user = self.create_random_user().await?;
    let access_policy_properties = InitialAccessPolicyProperties {
      action_id: action.id,
      permission_level: crate::resources::access_policy::ActionPermissionLevel::User,
      is_inheritance_enabled: true,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user.id),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Server,
      ..Default::default()
    };

    let access_policy = AccessPolicy::create(&access_policy_properties, &self.database_pool).await?;

    return Ok(access_policy);

  }

  pub async fn create_server_access_policy(&self, user_id: &Uuid, action_id: &Uuid, permission_level: &ActionPermissionLevel) -> Result<AccessPolicy, TestSlashstepServerError> {

    let access_policy = AccessPolicy::create(&InitialAccessPolicyProperties {
      action_id: action_id.clone(),
      permission_level: permission_level.clone(),
      is_inheritance_enabled: true,
      principal_type: crate::resources::access_policy::AccessPolicyPrincipalType::User,
      principal_user_id: Some(user_id.clone()),
      scoped_resource_type: crate::resources::access_policy::AccessPolicyResourceType::Server,
      ..Default::default()
    }, &self.database_pool).await?;

    return Ok(access_policy);

  }

  pub async fn create_random_workspace(&self) -> Result<Workspace, TestSlashstepServerError> {

    let workspace_properties = InitialWorkspaceProperties {
      name: Uuid::now_v7().to_string(),
      display_name: Uuid::now_v7().to_string(),
      description: Some(Uuid::now_v7().to_string())
    };

    let workspace = Workspace::create(&workspace_properties, &self.database_pool).await?;

    return Ok(workspace);

  }

}
