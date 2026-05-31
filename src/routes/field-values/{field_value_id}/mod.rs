use crate::{
    AppState, HTTPError,
    middleware::{authentication_middleware, http_transaction_middleware, rate_limit_middleware},
    resources::{
        ResourceType,
        access_policy::PermissionLevel,
        action_log_entry::{
            ActionLogEntry, ActionLogEntryActorType, InitialActionLogEntryProperties,
        },
        app::App,
        app_authorization::AppAuthorization,
        field_value::{EditableFieldValueProperties, FieldValue},
        http_transaction::HTTPTransaction,
        server_log_entry::ServerLogEntry,
        user::User,
    },
    routes::{GetResourceResponseBody, PatchResourceResponseBody},
    utilities::route_handler_utilities::{
        get_action_by_name, get_action_log_entry_expiration_timestamp, get_field_value_by_id,
        get_principal_type_and_id_from_principal, get_request_body_without_json_rejection,
        get_uuid_from_string, is_authenticated_user_anonymous, validate_decimal_is_within_range,
        validate_field_length, verify_delegate_permissions, verify_principal_permissions,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, State, rejection::JsonRejection},
};
use reqwest::StatusCode;
/*
 *
 * Any functionality for /field-values/{field_value_id} should be handled here.
 *
 * Programmers:
 * - Christian Toney (https://christiantoney.com)
 *
 * © 2026 Beastslash LLC
 *
 */
use crate::utilities::route_handler_utilities::create_trace_layer_span;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{trace, info};

#[path = "./access-policies/mod.rs"]
pub mod access_policies;

/// GET /field-values/{field_value_id}
///
/// Gets a field choice by its ID.
#[axum::debug_handler]
async fn handle_get_field_value_request(
    Path(field_value_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<Json<GetResourceResponseBody<FieldValue>>, HTTPError> {
    let field_value_id = get_uuid_from_string(
        &field_value_id,
        "field value",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_field_value =
        get_field_value_by_id(&field_value_id, &http_transaction, &state.database_pool).await?;
    let get_field_values_action =
        get_action_by_name("fieldValues.get", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &get_field_values_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::FieldValue,
        Some(&target_field_value.id),
        &get_field_values_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: get_field_values_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::FieldValue,
            target_field_value_id: Some(target_field_value.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully returned field value {}.", target_field_value.id);

    let response_body = GetResourceResponseBody {
        data: target_field_value.clone(),
    };

    Ok(Json(response_body))
}

/// DELETE /field-values/{field_value_id}
///
/// Deletes a field value by its ID.
#[axum::debug_handler]
async fn handle_delete_field_value_request(
    Path(field_value_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
) -> Result<StatusCode, HTTPError> {
    let field_value_id = get_uuid_from_string(
        &field_value_id,
        "field value",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let target_field_value =
        get_field_value_by_id(&field_value_id, &http_transaction, &state.database_pool).await?;
    let delete_field_values_action = get_action_by_name(
        "fieldValues.delete",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &delete_field_values_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::FieldValue,
        Some(&target_field_value.id),
        &delete_field_values_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    if let Err(error) = target_field_value.delete(&state.database_pool).await {
        let http_error = HTTPError::InternalServerError(Some(format!(
            "Failed to delete field value: {:?}",
            error
        )));
        http_error.log();
        return Err(http_error);
    }

    let expiration_timestamp =
        get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: delete_field_values_action.id,
            http_transaction_id: Some(http_transaction.id),
            expiration_timestamp,
            reason: None, // TODO: Support reasons.
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::FieldValue,
            target_field_value_id: Some(target_field_value.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();

    info!("Successfully deleted field value {}.", target_field_value.id);
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /field-values/{field_value_id}
///
/// Updates a field value by its ID.
#[axum::debug_handler]
async fn handle_patch_field_value_request(
    Path(field_value_id): Path<String>,
    State(state): State<AppState>,
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<EditableFieldValueProperties>, JsonRejection>,
) -> Result<Json<PatchResourceResponseBody<FieldValue>>, HTTPError> {
    let updated_field_value_properties =
        get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool)
            .await?;
    if let Some(Some(field_value_text_value)) = &updated_field_value_properties.text_value {
        validate_field_length(
            field_value_text_value,
            "fieldValues.maximumTextValueLength",
            "text_value",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    if let Some(Some(field_value_number_value)) = &updated_field_value_properties.number_value {
        validate_decimal_is_within_range(
            field_value_number_value,
            "fieldValues.minimumNumberValue",
            "fieldValues.maximumNumberValue",
            "number_value",
            &http_transaction,
            &state.database_pool,
        )
        .await?;
    }
    let field_value_id = get_uuid_from_string(
        &field_value_id,
        "field value",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    let original_target_field_value =
        get_field_value_by_id(&field_value_id, &http_transaction, &state.database_pool).await?;
    let update_access_policy_action = get_action_by_name(
        "fieldValues.update",
        &http_transaction,
        &state.database_pool,
    )
    .await?;
    verify_delegate_permissions(
        authenticated_app_authorization
            .as_ref()
            .map(|app_authorization| &app_authorization.id),
        &update_access_policy_action.id,
        &http_transaction.id,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;
    let (principal_type, principal_id) = get_principal_type_and_id_from_principal(
        authenticated_user.as_ref(),
        authenticated_app.as_ref(),
    )?;
    verify_principal_permissions(
        &principal_type,
        &principal_id,
        is_authenticated_user_anonymous(authenticated_user.as_ref()),
        &ResourceType::FieldValue,
        Some(&original_target_field_value.id),
        &update_access_policy_action,
        &http_transaction,
        &PermissionLevel::User,
        &state.database_pool,
    )
    .await?;

    trace!("Updating field value {}...", original_target_field_value.id);
    let updated_target_field_value = match original_target_field_value
        .update(&updated_field_value_properties, &state.database_pool)
        .await
    {
        Ok(updated_target_field_value) => updated_target_field_value,

        Err(error) => {
            let http_error = HTTPError::InternalServerError(Some(format!(
                "Failed to update field value {}: {:?}",
                original_target_field_value.id, error
            )));
            http_error.log();
            return Err(http_error);
        }
    };

    ActionLogEntry::create(
        &InitialActionLogEntryProperties {
            action_id: update_access_policy_action.id,
            http_transaction_id: Some(http_transaction.id),
            actor_type: if authenticated_user.is_some() {
                ActionLogEntryActorType::User
            } else {
                ActionLogEntryActorType::App
            },
            actor_user_id: authenticated_user
                .as_ref()
                .map(|authenticated_user| authenticated_user.id),
            actor_app_id: authenticated_app
                .as_ref()
                .map(|authenticated_app| authenticated_app.id),
            target_resource_type: ResourceType::FieldValue,
            target_field_value_id: Some(updated_target_field_value.id),
            ..Default::default()
        },
        &state.database_pool,
    )
    .await
    .ok();
    info!("Successfully updated field value {}.", updated_target_field_value.id);

    let response_body = PatchResourceResponseBody {
        data: updated_target_field_value,
    };

    Ok(Json(response_body))
}

pub fn get_router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route(
            "/field-values/{field_value_id}",
            axum::routing::get(handle_get_field_value_request),
        )
        .route(
            "/field-values/{field_value_id}",
            axum::routing::delete(handle_delete_field_value_request),
        )
        .route(
            "/field-values/{field_value_id}",
            axum::routing::patch(handle_patch_field_value_request),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware::verify_absolute_maximum_rate_limits,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_user,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authentication_middleware::authenticate_app,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http_transaction_middleware::create_http_transaction,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(create_trace_layer_span))
        .merge(access_policies::get_router(state.clone()))
}
