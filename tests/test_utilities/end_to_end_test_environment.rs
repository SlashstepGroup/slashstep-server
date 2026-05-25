use std::{net::SocketAddr, sync::Arc};

use axum_test::{TestServer, TestServerConfig};
use deadpool_postgres::tokio_postgres;
use postgres::NoTls;
use reqwest::StatusCode;
use slashstep_server::{
    AppState, DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT, import_env_file,
    initialize_required_tables,
    predefinitions::{
        initialize_predefined_actions, initialize_predefined_configurations,
        initialize_predefined_groups, initialize_predefined_roles,
    },
    resources::{
        access_policy::AccessPolicy,
        membership::{
            InitialMembershipProperties, Membership, MembershipParentResourceType,
            MembershipPrincipalType,
        },
        role::{PredefinedRoleType, Role, RoleParentResourceType},
        session::Session,
        user::{InitialUserProperties, User},
    },
    routes::{
        CreateResourceResponseBody, GetResourceResponseBody,
        access_policies::CreateServerAccessPolicyRequestBody,
    },
};
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::valkey::VALKEY_PORT;
use uuid::Uuid;

use crate::test_utilities::test_slashstep_server_error::TestSlashstepServerError;

pub struct EndToEndTestEnvironment {
    pub database_pool: deadpool_postgres::Pool,
    #[allow(dead_code)]
    pub redis_pool: deadpool_redis::Pool,
    #[allow(dead_code)]
    pub postgres_container: Arc<ContainerAsync<testcontainers_modules::postgres::Postgres>>,
    #[allow(dead_code)]
    pub redis_container: Arc<ContainerAsync<testcontainers_modules::valkey::Valkey>>,
    pub test_server: TestServer,
}

impl EndToEndTestEnvironment {
    pub async fn create_server_access_policy(
        &self,
        create_server_access_policy_request_body: &CreateServerAccessPolicyRequestBody,
    ) -> Result<AccessPolicy, TestSlashstepServerError> {
        let create_access_policy_response = self
            .test_server
            .post("/access-policies")
            .json(&serde_json::json!(create_server_access_policy_request_body))
            .await;

        assert_eq!(
            create_access_policy_response.status_code(),
            StatusCode::CREATED
        );

        let create_access_policy_response_body: CreateResourceResponseBody<AccessPolicy> =
            create_access_policy_response.json();
        let access_policy = create_access_policy_response_body.data;

        return Ok(access_policy);
    }

    pub async fn start_postgresql_container()
    -> Arc<ContainerAsync<testcontainers_modules::postgres::Postgres>> {
        println!("Starting PostgreSQL test server...");
        let postgres_container = Arc::new(
            testcontainers_modules::postgres::Postgres::default()
                .with_tag("18")
                .start()
                .await
                .expect("Failed to start PostgreSQL test server"),
        );

        return postgres_container;
    }

    pub async fn start_valkey_container()
    -> Arc<ContainerAsync<testcontainers_modules::valkey::Valkey>> {
        println!("Starting Valkey test server...");
        let valkey_container = Arc::new(
            testcontainers_modules::valkey::Valkey::default()
                .with_tag("latest")
                .start()
                .await
                .expect("Failed to start Valkey test server"),
        );

        return valkey_container;
    }

    pub async fn new() -> Result<Self, TestSlashstepServerError> {
        import_env_file();

        let postgres_container = Self::start_postgresql_container().await;
        let postgres_host = postgres_container.get_host().await?;
        let postgres_port = postgres_container.get_host_port_ipv4(5432).await?;

        println!("Signing into PostgreSQL test server...");
        let mut postgres_config = tokio_postgres::Config::new();
        postgres_config.host(postgres_host.to_string());
        postgres_config.port(postgres_port);
        postgres_config.user("postgres");
        postgres_config.password("postgres");
        postgres_config.dbname("postgres");
        let manager_config = deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        };
        let manager = deadpool_postgres::Manager::from_config(
            postgres_config.clone(),
            NoTls,
            manager_config.clone(),
        );
        let database_pool = deadpool_postgres::Pool::builder(manager)
            .max_size(DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT as usize)
            .build()?;

        initialize_required_tables(&database_pool).await?;
        initialize_predefined_actions(&database_pool).await?;
        initialize_predefined_roles(&database_pool).await?;
        initialize_predefined_groups(&database_pool).await?;
        initialize_predefined_configurations(&database_pool).await?;

        println!("Signing into Valkey test server...");
        let valkey_container = Self::start_valkey_container().await;
        let valkey_host = valkey_container.get_host().await?;
        let valkey_port = valkey_container.get_host_port_ipv4(VALKEY_PORT).await?;
        let valkey_url = format!("redis://{valkey_host}:{valkey_port}");
        let valkey_config = deadpool_redis::Config::from_url(valkey_url);
        let valkey_pool = valkey_config.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

        let state = AppState {
            database_pool: database_pool.clone(),
            redis_pool: valkey_pool.clone(),
        };

        let router = slashstep_server::routes::get_router(state.clone())
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
        let test_server = TestServer::new_with_config(
            router,
            TestServerConfig {
                save_cookies: true,
                ..Default::default()
            },
        );
        let environment = EndToEndTestEnvironment {
            database_pool,
            postgres_container,
            redis_pool: valkey_pool,
            redis_container: valkey_container,
            test_server,
        };

        return Ok(environment);
    }

    pub async fn create_admin_user(
        &self,
        plain_text_password: Option<&String>,
    ) -> Result<User, TestSlashstepServerError> {
        let user = User::create(
            &InitialUserProperties {
                username: Some(Uuid::now_v7().to_string()),
                hashed_password: Some(User::hash_password(
                    plain_text_password.unwrap_or(&Uuid::now_v7().to_string()),
                )?),
                display_name: None,
                is_anonymous: false,
                ip_address: None,
            },
            &self.database_pool,
        )
        .await?;

        let server_admins_role = Role::get_by_predefined_role_type(
            &RoleParentResourceType::Server,
            None,
            &PredefinedRoleType::ServerAdmins,
            &self.database_pool,
        )
        .await?;

        Membership::create(
            &InitialMembershipProperties {
                parent_resource_type: MembershipParentResourceType::Role,
                parent_group_id: None,
                parent_role_id: Some(server_admins_role.id),
                principal_type: MembershipPrincipalType::User,
                principal_user_id: Some(user.id),
                principal_app_id: None,
                principal_group_id: None,
            },
            &self.database_pool,
        )
        .await?;

        return Ok(user);
    }

    pub async fn create_random_user(
        &self,
        plain_text_password: Option<&String>,
    ) -> Result<User, TestSlashstepServerError> {
        let username = Uuid::now_v7().to_string();
        let plain_text_password = plain_text_password
            .cloned()
            .unwrap_or_else(|| Uuid::now_v7().to_string());
        let create_user_response = self
            .test_server
            .post("/users")
            .json(&serde_json::json!({
              "username": username,
              "password": plain_text_password
            }))
            .await;

        assert_eq!(create_user_response.status_code(), StatusCode::CREATED);

        let create_user_response_body: CreateResourceResponseBody<User> =
            create_user_response.json();
        let user = create_user_response_body.data;

        return Ok(user);
    }

    pub async fn create_session(
        &self,
        username: &String,
        plain_text_password: &String,
    ) -> Result<Session, TestSlashstepServerError> {
        let create_session_response = self
            .test_server
            .post("/sessions")
            .json(&serde_json::json!({
              "username": username,
              "password": plain_text_password
            }))
            .await;

        assert_eq!(create_session_response.status_code(), StatusCode::CREATED);

        let create_session_response_body: CreateResourceResponseBody<Session> =
            create_session_response.json();
        let session = create_session_response_body.data;

        return Ok(session);
    }

    pub async fn get_access_policy_by_id(
        &self,
        access_policy_id: &Uuid,
    ) -> Result<AccessPolicy, TestSlashstepServerError> {
        let get_access_policy_response = self
            .test_server
            .get(&format!("/access-policies/{access_policy_id}"))
            .await;

        assert_eq!(get_access_policy_response.status_code(), StatusCode::OK);

        let get_access_policy_response_body: GetResourceResponseBody<AccessPolicy> =
            get_access_policy_response.json();
        let access_policy = get_access_policy_response_body.data;

        return Ok(access_policy);
    }

    // pub async fn get_server_action_by_name(
    //     &self,
    //     action_name: &String,
    // ) -> Result<Action, TestSlashstepServerError> {
    //     let get_action_response = self
    //         .test_server
    //         .get(&format!("/actions"))
    //         .add_query_param("query", format!("name = {action_name}"))
    //         .await;

    //     assert_eq!(get_action_response.status_code(), StatusCode::OK);

    //     let list_actions_response_body: ListResourcesResponseBody<Action> =
    //         get_action_response.json();
    //     let actions = list_actions_response_body.data;
    //     let action = actions
    //         .into_iter()
    //         .find(|action| action.name == *action_name)
    //         .ok_or_else(|| {
    //             TestSlashstepServerError::ResourceError(ResourceError::NotFound(format!(
    //                 "Action with name {action_name} not found."
    //             )))
    //         })?;

    //     return Ok(action);
    // }
}
