use crate::{
    AppState, HTTPError, get_json_web_token_public_key,
    resources::{
        ResourceError,
        app::App,
        app_authorization::AppAuthorization,
        group::{Group, GroupParentResourceType, PredefinedGroupType},
        http_transaction::HTTPTransaction,
        membership::{
            InitialMembershipProperties, Membership, MembershipParentResourceType,
            MembershipPrincipalType,
        },
        session::Session,
        session_credential::{SessionCredential, SessionCredentialTokenClaims},
        user::{InitialUserProperties, User},
    },
    utilities::route_handler_utilities::{get_app_by_id, get_app_credential_by_id},
};
use axum::{
    Extension,
    body::Body,
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use reqwest::header;
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

async fn get_jwt_public_key(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
) -> Result<String, HTTPError> {
    let jwt_public_key = match get_json_web_token_public_key().await {
        Ok(jwt_public_key) => jwt_public_key,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!("{:?}", error)));
            http_error.log();
            return Err(http_error);
        }
    };

    Ok(jwt_public_key)
}

pub async fn get_decoding_key(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
    jwt_public_key: &str,
) -> Result<jsonwebtoken::DecodingKey, HTTPError> {
    let decoding_key = match jsonwebtoken::DecodingKey::from_ed_pem(jwt_public_key.as_bytes()) {
        Ok(decoding_key) => decoding_key,
        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to decode JWT public key: {:?}",
                error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    Ok(decoding_key)
}

async fn get_decoded_claims(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
    session_token: &str,
    decoding_key: &jsonwebtoken::DecodingKey,
    validation: &jsonwebtoken::Validation,
) -> Result<jsonwebtoken::TokenData<SessionCredentialTokenClaims>, HTTPError> {
    let decoded_claims = match jsonwebtoken::decode::<SessionCredentialTokenClaims>(
        &session_token,
        decoding_key,
        validation,
    ) {
        Ok(decoded_claims) => decoded_claims,
        Err(error) => {
            let http_error = match &error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => HTTPError::Unauthorized(Some(
                    "Please provide a valid session token.".to_string(),
                )),

                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claims) => {
                    warn!("Missing required claim \"{}\" in session token.", claims);
                    HTTPError::Unauthorized(Some(
                        "Please provide a valid session token.".to_string(),
                    ))
                }

                _ => HTTPError::InternalServerError(Some(format!(
                    "Failed to decode session token: {:?}",
                    error
                ))),
            };

            http_error.log();
            return Err(http_error);
        }
    };

    Ok(decoded_claims)
}

async fn get_user_by_id(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
    user_id: &Uuid,
) -> Result<User, HTTPError> {
    let user = match User::get_by_id(user_id, database_pool).await {
        Ok(user) => user,
        Err(error) => {
            let http_error = match error {
                // For this middleware, signalling that the token is invalid is a higher priority than the user not existing.
                ResourceError::NotFoundError(_) => HTTPError::Unauthorized(Some(
                    "Please provide a valid session token.".to_string(),
                )),
                _ => HTTPError::InternalServerError(Some(error.to_string())),
            };

            http_error.log();

            return Err(http_error);
        }
    };

    Ok(user)
}

async fn get_session_by_id(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
    session_id: &Uuid,
) -> Result<Session, HTTPError> {
    let session = match Session::get_by_id(session_id, database_pool).await {
        Ok(session) => session,
        Err(error) => {
            let http_error = match error {
                ResourceError::NotFoundError(_) => {
                    HTTPError::Unauthorized(Some(format!("Please provide a valid session token.")))
                }
                ResourceError::PostgresError(error) => match error.as_db_error() {
                    Some(db_error) => {
                        HTTPError::InternalServerError(Some(format!("{:?}", db_error)))
                    }

                    None => HTTPError::InternalServerError(Some(format!("{:?}", error))),
                },
                _ => HTTPError::InternalServerError(Some(error.to_string())),
            };

            http_error.log();

            return Err(http_error);
        }
    };

    Ok(session)
}

async fn get_session_credential_by_id(
    http_transaction_id: &Uuid,
    database_pool: &deadpool_postgres::Pool,
    session_id: &Uuid,
) -> Result<SessionCredential, HTTPError> {
    let session = match SessionCredential::get_by_id(session_id, database_pool).await {
        Ok(session) => session,
        Err(error) => {
            let http_error = match error {
                ResourceError::NotFoundError(_) => {
                    HTTPError::Unauthorized(Some(format!("Please provide a valid session token.")))
                }
                ResourceError::PostgresError(error) => match error.as_db_error() {
                    Some(db_error) => {
                        HTTPError::InternalServerError(Some(format!("{:?}", db_error)))
                    }

                    None => HTTPError::InternalServerError(Some(format!("{:?}", error))),
                },
                _ => HTTPError::InternalServerError(Some(error.to_string())),
            };

            http_error.log();

            return Err(http_error);
        }
    };

    Ok(session)
}

#[axum_macros::debug_middleware]
pub async fn authenticate_user(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    cookie_jar: CookieJar,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, HTTPError> {
    // Get the cookie from the request.
    let Some(session_token) = cookie_jar.get("session_access_token") else {
        // Use an anonymous user.
        trace!("No user token found in request. Checking for existing anonymous user...");

        let anonymous_user =
            match User::get_by_ip_address(&http_transaction.ip_address, &state.database_pool).await
            {
                Ok(anonymous_user) => Arc::new(anonymous_user),

                Err(error) => match error {
                    ResourceError::NotFoundError(_) => {
                        trace!("No existing anonymous user found. Creating a new one...");

                        match User::create(
                            &InitialUserProperties {
                                username: None,
                                display_name: None,
                                hashed_password: None,
                                is_anonymous: true,
                                ip_address: Some(http_transaction.ip_address),
                            },
                            &state.database_pool,
                        )
                        .await
                        {
                            Ok(anonymous_user) => Arc::new(anonymous_user),

                            Err(error) => {
                                let http_error = HTTPError::InternalServerError(Some(format!(
                                    "Failed to create anonymous user: {:?}",
                                    error
                                )));
                                http_error.log();
                                return Err(http_error);
                            }
                        }
                    }

                    _ => {
                        let http_error = HTTPError::InternalServerError(Some(format!(
                            "Failed to get anonymous user: {:?}",
                            error
                        )));
                        http_error.log();
                        return Err(http_error);
                    }
                },
            };

        trace!("Getting anonymous users group...");
        let anonymous_users_group = match Group::get_protected_group_by_type(
            &GroupParentResourceType::Server,
            None,
            &PredefinedGroupType::AnonymousUsers,
            &state.database_pool,
        )
        .await
        {
            Ok(anonymous_users_group) => anonymous_users_group,

            Err(error) => {
                let http_error = HTTPError::InternalServerError(Some(format!(
                    "Failed to get anonymous users group: {:?}",
                    error
                )));
                http_error.log();
                return Err(http_error);
            }
        };
        trace!(
            "Checking if user {} is in the anonymous users group...",
            anonymous_user.id
        );
        let memberships = match Membership::list(
            &format!(
                "parent_group_id = '{}' and principal_type = 'User' and principal_user_id = '{}'",
                anonymous_users_group.id, anonymous_user.id
            ),
            &state.database_pool,
            None,
            None,
        )
        .await
        {
            Ok(memberships) => memberships,

            Err(error) => {
                let http_error = HTTPError::InternalServerError(Some(format!(
                    "Failed to get memberships: {:?}",
                    error
                )));
                http_error.log();
                return Err(http_error);
            }
        };

        if memberships.is_empty() {
            trace!("User is not in the anonymous users group. Creating a new group membership...");
            Membership::create(
                &InitialMembershipProperties {
                    parent_resource_type: MembershipParentResourceType::Group,
                    parent_group_id: Some(anonymous_users_group.id),
                    principal_type: MembershipPrincipalType::User,
                    principal_user_id: Some(anonymous_user.id),
                    ..Default::default()
                },
                &state.database_pool,
            )
            .await
            .ok();
        }

        trace!("Adding user {} to request extensions...", anonymous_user.id);

        request
            .extensions_mut()
            .insert(Some(anonymous_user.clone()));

        info!("Authenticated as anonymous user {}.", anonymous_user.id);

        return Ok(next.run(request).await);
    };

    let session_token = session_token.value().to_string();

    // Make sure the user token is valid.
    trace!("Decoding session token...");

    let jwt_public_key = get_jwt_public_key(&http_transaction.id, &state.database_pool).await?;
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    let decoding_key =
        get_decoding_key(&http_transaction.id, &state.database_pool, &jwt_public_key).await?;
    let decoded_claims = get_decoded_claims(
        &http_transaction.id,
        &state.database_pool,
        &session_token,
        &decoding_key,
        &validation,
    )
    .await?;

    // Set the user and session in the request extensions.
    let session_credential_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
        Ok(session_credential_id) => session_credential_id,
        Err(_) => {
            let http_error =
                HTTPError::Unauthorized(Some("Please provide a valid session token.".to_string()));
            http_error.log();
            return Err(http_error);
        }
    };
    let session_id = match Uuid::parse_str(&decoded_claims.claims.session_id) {
        Ok(session_id) => session_id,
        Err(_) => {
            let http_error =
                HTTPError::Unauthorized(Some("Please provide a valid session token.".to_string()));
            http_error.log();
            return Err(http_error);
        }
    };
    let user_id = match Uuid::parse_str(&decoded_claims.claims.sub) {
        Ok(user_id) => user_id,
        Err(_) => {
            let http_error =
                HTTPError::Unauthorized(Some("Please provide a valid session token.".to_string()));
            http_error.log();
            return Err(http_error);
        }
    };
    trace!("Getting session credential...");
    let session_credential = get_session_credential_by_id(
        &http_transaction.id,
        &state.database_pool,
        &session_credential_id,
    )
    .await?;
    trace!("Getting session from session credential...");
    let session =
        get_session_by_id(&http_transaction.id, &state.database_pool, &session_id).await?;
    trace!("Checking if session is still active...");
    if session.expiration_date < chrono::Utc::now() {
        let http_error =
            HTTPError::Unauthorized(Some("Please provide a valid session token.".to_string()));
        http_error.log();
        return Err(http_error);
    }
    trace!("Getting user from session credential...");
    let user = get_user_by_id(&http_transaction.id, &state.database_pool, &user_id).await?;
    trace!("Adding user and session to request extensions...");
    request
        .extensions_mut()
        .insert(Some(Arc::new(session_credential.clone())));
    request
        .extensions_mut()
        .insert(Some(Arc::new(user.clone())));
    request
        .extensions_mut()
        .insert(Some(Arc::new(session.clone())));

    info!("Successfully authenticated as user {}.", user_id);

    let response = next.run(request).await;

    Ok(response)
}

#[axum_macros::debug_middleware]
pub async fn authenticate_app(
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, HTTPError> {
    request
        .extensions_mut()
        .insert(None as Option<Arc<AppAuthorization>>); // TODO: Add support for app authorizations.

    // Get the cookie from the request.
    let Some(authorization_token) = headers.get(header::AUTHORIZATION) else {
        debug!("No app token found in request.");
        request.extensions_mut().insert(None as Option<Arc<App>>);
        return Ok(next.run(request).await);
    };

    let authorization_token = match authorization_token.to_str() {
        Ok(authorization_token) => authorization_token,

        Err(_) => {
            let http_error =
                HTTPError::BadRequest(Some("Please provide a valid app token.".to_string()));
            warn!("{}", http_error);
            return Err(http_error);
        }
    };

    if !authorization_token.starts_with("App ") {
        let http_error =
            HTTPError::Unauthorized(Some("Please provide a valid app token.".to_string()));
        warn!("{}", http_error);
        return Err(http_error);
    }

    let authorization_token = authorization_token.to_string().replace("App ", "");

    // Make sure the user token is valid.
    trace!("Decoding app token...");

    let jwt_public_key = get_jwt_public_key(&http_transaction.id, &state.database_pool).await?;
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    let decoding_key =
        get_decoding_key(&http_transaction.id, &state.database_pool, &jwt_public_key).await?;
    let decoded_claims = get_decoded_claims(
        &http_transaction.id,
        &state.database_pool,
        &authorization_token,
        &decoding_key,
        &validation,
    )
    .await?;

    // Set the user and session in the request extensions.
    let app_credential_id = match Uuid::parse_str(&decoded_claims.claims.jti) {
        Ok(app_credential_id) => app_credential_id,

        Err(_) => {
            let http_error = HTTPError::InternalServerError(Some(
                "App credential ID is not a valid UUID.".to_string(),
            ));
            error!("{}", http_error);
            return Err(http_error);
        }
    };

    let app_credential =
        match get_app_credential_by_id(&app_credential_id, &http_transaction, &state.database_pool)
            .await
        {
            Ok(app_credential) => app_credential,

            Err(error) => match error {
                HTTPError::BadRequest(_) | HTTPError::NotFoundError(_) => {
                    let http_error = HTTPError::Unauthorized(Some(
                        "Please provide a valid app token.".to_string(),
                    ));
                    http_error.log();
                    return Err(http_error);
                }

                _ => return Err(error),
            },
        };

    let app = match get_app_by_id(
        &app_credential.app_id,
        &http_transaction,
        &state.database_pool,
    )
    .await
    {
        Ok(app) => app,

        Err(error) => match error {
            HTTPError::BadRequest(_) | HTTPError::NotFoundError(_) => {
                let http_error =
                    HTTPError::Unauthorized(Some("Please provide a valid app token.".to_string()));
                http_error.log();
                return Err(http_error);
            }

            _ => return Err(error),
        },
    };

    trace!("Adding app and app credential to request extensions...");
    request.extensions_mut().insert(Some(Arc::new(app.clone())));
    request
        .extensions_mut()
        .insert(Some(Arc::new(app_credential.clone())));

    debug!("Successfully authenticated as app {}.", app.id);
    let response = next.run(request).await;
    Ok(response)
}
