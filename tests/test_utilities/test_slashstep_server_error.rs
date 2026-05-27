use slashstep_server::{SlashstepServerError, resources::ResourceError};
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
    PKCS8Error(#[from] ed25519_dalek::pkcs8::Error),

    #[error(transparent)]
    RedisCreatePoolError(#[from] deadpool_redis::CreatePoolError),

    #[error(transparent)]
    SPKIError(#[from] ed25519_dalek::pkcs8::spki::Error),

    #[error(transparent)]
    SlashstepServerError(#[from] SlashstepServerError),

    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),

    #[error(transparent)]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    PostgreSQLEmbeddedError(#[from] postgresql_embedded::Error),
}
