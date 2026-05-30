use std::net::SocketAddr;

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;
use deadpool_postgres::{Pool, tokio_postgres};
use local_ip_address::local_ip;
use postgres::NoTls;
use slashstep_server::{
    AppState, DEFAULT_APP_PORT, DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT, SlashstepServerError,
    get_environment_variable, import_env_file, initialize_required_tables,
    predefinitions::{
        initialize_predefined_actions, initialize_predefined_configurations,
        initialize_predefined_groups, initialize_predefined_roles,
    },
    routes, setup_admin_user_if_necessary,
};
use tokio::net::TcpListener;

async fn create_database_pool() -> Result<deadpool_postgres::Pool, SlashstepServerError> {
    let host = get_environment_variable("POSTGRESQL_HOST")?;
    let username = get_environment_variable("POSTGRESQL_USERNAME")?;
    let database_name = get_environment_variable("POSTGRESQL_DATABASE_NAME")?;
    let password_path = get_environment_variable("POSTGRESQL_PASSWORD_FILE_PATH")?;

    println!(
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
    postgres_config.user(username);
    postgres_config.dbname(database_name);
    postgres_config.password(password);
    let manager_config = deadpool_postgres::ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Fast,
    };
    let manager = deadpool_postgres::Manager::from_config(postgres_config, NoTls, manager_config);

    let maximum_postgres_connection_count_string = match get_environment_variable(
        "MAXIMUM_POSTGRESQL_CONNECTION_COUNT",
    ) {
        Ok(maximum_postgres_connection_count) => maximum_postgres_connection_count,
        Err(_) => {
            println!("{}", format!("Please set a MAXIMUM_POSTGRESQL_CONNECTION_COUNT environment variable. Defaulting to {}.", DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT).yellow());
            DEFAULT_MAXIMUM_POSTGRESQL_CONNECTION_COUNT.to_string()
        }
    };
    let maximum_postgres_connection_count =
        maximum_postgres_connection_count_string.parse::<usize>()?;

    let pool = Pool::builder(manager)
        .max_size(maximum_postgres_connection_count)
        .build()?;
    Ok(pool)
}

async fn create_redis_pool() -> Result<deadpool_redis::Pool, SlashstepServerError> {
    let redis_url = get_environment_variable("REDIS_URL")?;
    let redis_config = deadpool_redis::Config::from_url(redis_url);
    let redis_pool = redis_config.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    Ok(redis_pool)
}

fn print_shutdown_message() {
    println!("{}", "Slashstep Server is shutting down...".blue());
}

async fn gracefully_shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
      _ = ctrl_c => {

        print_shutdown_message();

      },
      _ = terminate => {

        print_shutdown_message();

      },
    }
}

fn get_app_port_string() -> String {
    match std::env::var("APP_PORT") {
        Ok(app_port) => app_port,
        Err(_) => {
            println!(
                "{}",
                format!(
                    "Please set an APP_PORT environment variable. Defaulting to {}.",
                    DEFAULT_APP_PORT
                )
                .yellow()
            );
            DEFAULT_APP_PORT.to_string()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), SlashstepServerError> {
    println!("Slashstep Server v{}", env!("CARGO_PKG_VERSION"));

    import_env_file();
    let state = AppState {
        database_pool: create_database_pool().await?,
        redis_pool: create_redis_pool().await?,
    };

    initialize_required_tables(&state.database_pool).await?;
    initialize_predefined_actions(&state.database_pool).await?;
    initialize_predefined_roles(&state.database_pool).await?;
    initialize_predefined_configurations(&state.database_pool).await?;
    initialize_predefined_groups(&state.database_pool).await?;
    setup_admin_user_if_necessary(&state.database_pool).await?;

    let app_port = get_app_port_string();
    let router = routes::get_router(state.clone()).with_state(state);
    let app_ip = local_ip()?;

    if get_environment_variable("SHOULD_USE_SELF_SIGNED_TLS_CERTIFICATE")
        .unwrap_or("FALSE".to_string())
        == "TRUE"
    {
        let certificate_path = get_environment_variable("SELF_SIGNED_TLS_CERTIFICATE_PATH")?;
        let private_key_path = get_environment_variable("SELF_SIGNED_TLS_PRIVATE_KEY_PATH")?;
        let rustls_config = RustlsConfig::from_pem_file(certificate_path, private_key_path).await?;
        let address = SocketAddr::from(([0, 0, 0, 0], app_port.parse::<u16>()?));
        let handle = axum_server::Handle::new();
        let tokio_handle = handle.clone();
        tokio::spawn(async move {
            gracefully_shutdown().await;
            tokio_handle.graceful_shutdown(None);
        });
        println!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at https://localhost:{}, or your local network at https://{}:{}.", app_port, app_port, app_ip, app_port).green());
        axum_server::bind_rustls(address, rustls_config)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", app_port)).await?;
        println!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at http://localhost:{}, or your local network at http://{}:{}.", app_port, app_port, app_ip, app_port).green());
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(gracefully_shutdown())
        .await?;
    }

    return Ok(());
}
