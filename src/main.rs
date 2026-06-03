use std::{fs::{self}, net::SocketAddr, path::Path};

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;
use local_ip_address::local_ip;
use slashstep_server::{
    AppState, DEFAULT_APP_PORT, OpenSearchLayer, SlashstepServerConfig, SlashstepServerError, SlashstepServerNetworkConfig, TLSMode, create_database_pool, create_opensearch_client, create_redis_pool, get_environment_variable, import_env_file, initialize_required_tables, predefinitions::{
        initialize_predefined_actions, initialize_predefined_configurations,
        initialize_predefined_groups, initialize_predefined_roles,
    }, routes, run_opensearch_log_worker, setup_admin_user_if_necessary
};
use tokio::{net::TcpListener, sync::mpsc};
use tracing::{info, debug, trace, warn, error};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn print_shutdown_message() {
    info!("{}", "Slashstep Server is shutting down...".blue());
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

fn get_slashstep_server_config() -> Result<SlashstepServerConfig, SlashstepServerError> {
    let slashstep_server_config_file_path = get_environment_variable("SLASHSTEP_SERVER_CONFIG_FILE_PATH").unwrap_or("./slashstep-server.yml".to_string());
    let slashstep_server_config_file = fs::read_to_string(&slashstep_server_config_file_path)?;
    let slashstep_server_config: SlashstepServerConfig = match yaml_serde::from_str(&slashstep_server_config_file) {

        Ok(config) => config,
        Err(error) => {
            error!("Failed to read Slashstep Server configuration file at {}: {}. Please ensure that the file exists and is properly formatted.", slashstep_server_config_file_path, error);
            std::process::exit(1);
        }

    };
    Ok(slashstep_server_config)
}

#[tokio::main]
async fn main() -> Result<(), SlashstepServerError> {
    println!("Slashstep Server {}", env!("CARGO_PKG_VERSION"));
    import_env_file();

    let environment_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("off,{}=trace", env!("CARGO_CRATE_NAME"))));
    
    let (opensearch_sender, receiver) = mpsc::channel(100);
    let opensearch_layer = OpenSearchLayer {
        sender: opensearch_sender
    };
    tracing_subscriber::registry()
        .with(opensearch_layer)
        .with(tracing_subscriber::fmt::layer())
        .with(environment_filter)
        .init();

    let slashstep_server_config = get_slashstep_server_config()?;

    let opensearch_client = create_opensearch_client(slashstep_server_config.opensearch.as_ref())?;
    tokio::spawn(run_opensearch_log_worker(receiver, opensearch_client.clone()));

    let state = AppState {
        database_pool: create_database_pool(slashstep_server_config.postgresql.as_ref()).await?,
        redis_pool: create_redis_pool(slashstep_server_config.redis.as_ref()).await?,
        opensearch_client: opensearch_client
    };

    initialize_required_tables(&state.database_pool).await?;
    initialize_predefined_actions(&state.database_pool).await?;
    initialize_predefined_roles(&state.database_pool).await?;
    initialize_predefined_configurations(&state.database_pool).await?;
    initialize_predefined_groups(&state.database_pool).await?;
    setup_admin_user_if_necessary(slashstep_server_config.setup.as_ref(), &state.database_pool).await?;

    let slashstep_server_network_config = slashstep_server_config.network.clone().unwrap_or_default();
    let app_port = slashstep_server_network_config.port.unwrap_or(DEFAULT_APP_PORT);
    let router = routes::get_router(state.clone()).with_state(state);
    let app_ip = local_ip()?;
    let tls_mode = slashstep_server_config
        .network
        .unwrap_or_default()
        .tls_mode
        .clone()
        .unwrap_or(TLSMode::UseDemoCertificate);

    match tls_mode {
        
        TLSMode::UseDemoCertificate | TLSMode::UseCustomCertificate => {

            async fn get_rustls_config(slashstep_server_network_config: &SlashstepServerNetworkConfig) -> Result<RustlsConfig, SlashstepServerError> {

                let tls_mode = slashstep_server_network_config.tls_mode.unwrap_or(TLSMode::UseDemoCertificate);
                let demo_certificates_directory_path = slashstep_server_network_config.demo_certificates_directory_path.clone().unwrap_or("./demo-certificates".to_string());

                if tls_mode == TLSMode::UseDemoCertificate {

                    warn!("Slashstep Server is currently set to use a demo TLS certificate. This certificate is helpful for development and testing purposes, but it should not be used in production environments. The certificate is untrusted by default on end user systems. For production environments, please set up your own TLS certificate and private key, and set the SLASHSTEP_TLS_MODE environment variable to USE_CUSTOM_CERTIFICATE.");

                    fs::create_dir_all(&demo_certificates_directory_path)?;
                    if !Path::new(format!("{demo_certificates_directory_path}/slashstep-tls-certificate.pem").as_str()).exists() || !Path::new(format!("{demo_certificates_directory_path}/slashstep-tls-private-key.pem").as_str()).exists() {

                        trace!("Generating self-signed TLS certificate for demo purposes...");
                        let self_signed_certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
                        let certificate_pem = self_signed_certificate.cert.pem();
                        let private_key_pem = self_signed_certificate.signing_key.serialize_pem();
                        fs::write(format!("{demo_certificates_directory_path}/slashstep-tls-certificate.pem"), certificate_pem)?;
                        fs::write(format!("{demo_certificates_directory_path}/slashstep-tls-private-key.pem"), private_key_pem)?;
                        debug!("Demo TLS certificate and private key have been generated and saved to the demo certificates directory.");

                    }

                    let certificate_path = format!("{demo_certificates_directory_path}/slashstep-tls-certificate.pem");
                    let private_key_path = format!("{demo_certificates_directory_path}/slashstep-tls-private-key.pem");
                    let rustls_config = RustlsConfig::from_pem_file(certificate_path, private_key_path).await?;
                    return Ok(rustls_config);

                } else {

                    trace!("Using custom TLS certificate and private key specified by the SLASHSTEP_TLS_CERTIFICATE_PATH and SLASHSTEP_TLS_PRIVATE_KEY_PATH environment variables...");
                    let certificate_path = slashstep_server_network_config.demo_certificates_directory_path.clone().unwrap_or("./secrets/slashstep-tls-certificate.pem".to_string());
                    let private_key_path = slashstep_server_network_config.demo_certificates_directory_path.clone().unwrap_or("./secrets/slashstep-tls-private-key.pem".to_string());
                    let rustls_config = RustlsConfig::from_pem_file(certificate_path, private_key_path).await?;
                    return Ok(rustls_config);

                }

            }

            let rustls_config = get_rustls_config(&slashstep_server_network_config).await?;
            let address = SocketAddr::from(([0, 0, 0, 0], app_port));
            let handle = axum_server::Handle::new();
            let tokio_handle = handle.clone();
            tokio::spawn(async move {
                gracefully_shutdown().await;
                tokio_handle.graceful_shutdown(None);
            });
            info!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at https://localhost:{}, or your local network at https://{}:{}.", app_port, app_port, app_ip, app_port).green());
            axum_server::bind_rustls(address, rustls_config)
                .handle(handle)
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await?;

        },

        TLSMode::DisableTLS => {

            warn!("TLS is currently disabled. This may be helpful for development and testing purposes, but it should not be used in production environments. All communication with the server will be unencrypted, which is a security risk. Secure cookies may not work either. It is recommended to enable TLS in production environments to ensure the security of data transmitted between clients and the server.");
            let listener = TcpListener::bind(format!("0.0.0.0:{}", app_port)).await?;
            info!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at http://localhost:{}, or your local network at http://{}:{}.", app_port, app_port, app_ip, app_port).green());
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(gracefully_shutdown())
            .await?;
        }

    }

    return Ok(());
}
