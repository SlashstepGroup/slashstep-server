  /**
   * 
   * Any functionality for /items/{item_id}/field-values should be handled here.
   * 
   * Programmers: 
   * - Christian Toney (https://christiantoney.com)
   * 
   * © 2026 Beastslash LLC
   * 
   */

  #[cfg(test)]
  mod tests;

  use std::sync::Arc;
  use axum::{Extension, Json, Router, extract::{Path, Query, State, rejection::JsonRejection}};
  use axum_extra::response::ErasedJson;
  use pg_escape::quote_literal;
  use reqwest::StatusCode;
  use crate::{AppState, HTTPError, middleware::{authentication_middleware, http_transaction_middleware}, resources::{access_policy::{AccessPolicyResourceType, ActionPermissionLevel}, action_log_entry::{ActionLogEntry, ActionLogEntryActorType, ActionLogEntryTargetResourceType, InitialActionLogEntryProperties}, app::App, app_authorization::AppAuthorization, field_value::{DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT, FieldValue, FieldValueParentResourceType, InitialFieldValueProperties, InitialFieldValuePropertiesWithPredefinedParent}, http_transaction::HTTPTransaction, server_log_entry::ServerLogEntry, user::User}, utilities::{reusable_route_handlers::{ResourceListQueryParameters, list_resources}, route_handler_utilities::{AuthenticatedPrincipal, get_action_by_name, get_action_log_entry_expiration_timestamp, get_authenticated_principal, get_field_by_id, get_item_by_id, get_request_body_without_json_rejection, get_resource_hierarchy, get_uuid_from_string, validate_decimal_is_within_range, validate_field_length, verify_delegate_permissions, verify_principal_permissions}}};

  /// GET /items/{item_id}/field-values
  /// 
  /// Lists field values for an app credential.
  #[axum::debug_handler]
  async fn handle_list_field_values_request(
    Path(item_id): Path<String>,
    Query(query_parameters): Query<ResourceListQueryParameters>,
    State(state): State<AppState>, 
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>
  ) -> Result<ErasedJson, HTTPError> {

    let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
    let target_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
    let resource_hierarchy = get_resource_hierarchy(&target_item, &AccessPolicyResourceType::Item, &target_item.id, &http_transaction, &state.database_pool).await?;

    let query = format!(
      "parent_resource_type = 'Item' AND parent_item_id = {}{}", 
      quote_literal(&target_item.id.to_string()), 
      query_parameters.query.and_then(|query| Some(format!(" AND {}", query))).unwrap_or("".to_string())
    );
    
    let query_parameters = ResourceListQueryParameters {
      query: Some(query)
    };

    let response = list_resources(
      Query(query_parameters), 
      State(state), 
      Extension(http_transaction), 
      Extension(authenticated_user), 
      Extension(authenticated_app), 
      Extension(authenticated_app_authorization),
      resource_hierarchy, 
      ActionLogEntryTargetResourceType::Item, 
      Some(target_item.id), 
      |query, database_pool, individual_principal| Box::new(FieldValue::count(query, database_pool, individual_principal)),
      |query, database_pool, individual_principal| Box::new(FieldValue::list(query, database_pool, individual_principal)),
      "fieldValues.list", 
      DEFAULT_MAXIMUM_RESOURCE_LIST_LIMIT,
      "field values",
      "field value"
    ).await;
    
    return response;

  }

  /// POST /items/{item_id}/field-values
  /// 
  /// Creates a field value for an item.
  #[axum::debug_handler]
  async fn handle_create_field_value_request(
    Path(item_id): Path<String>,
    State(state): State<AppState>, 
    Extension(http_transaction): Extension<Arc<HTTPTransaction>>,
    Extension(authenticated_user): Extension<Option<Arc<User>>>,
    Extension(authenticated_app): Extension<Option<Arc<App>>>,
    Extension(authenticated_app_authorization): Extension<Option<Arc<AppAuthorization>>>,
    body: Result<Json<InitialFieldValuePropertiesWithPredefinedParent>, JsonRejection>
  ) -> Result<(StatusCode, Json<FieldValue>), HTTPError> {

    // Make sure the user can create field values for the target action.
    let item_id = get_uuid_from_string(&item_id, "item", &http_transaction, &state.database_pool).await?;
    let field_value_properties_json = get_request_body_without_json_rejection(body, &http_transaction, &state.database_pool).await?;
    if let Some(field_value_text_value) = &field_value_properties_json.text_value { 

      validate_field_length(field_value_text_value, "fieldValues.maximumTextValueLength", "text_value", &http_transaction, &state.database_pool).await?;

    }
    if let Some(field_value_number_value) = &field_value_properties_json.number_value {

      validate_decimal_is_within_range(field_value_number_value, "fieldValues.minimumNumberValue", "fieldValues.maximumNumberValue", "number_value", &http_transaction, &state.database_pool).await?;

    }
    let target_item = get_item_by_id(&item_id, &http_transaction, &state.database_pool).await?;
    let resource_hierarchy = get_resource_hierarchy(&target_item, &AccessPolicyResourceType::Item, &target_item.id, &http_transaction, &state.database_pool).await?;
    let create_field_values_action = get_action_by_name("fieldValues.create", &http_transaction, &state.database_pool).await?;
    verify_delegate_permissions(authenticated_app_authorization.as_ref().map(|app_authorization| &app_authorization.id), &create_field_values_action.id, &http_transaction.id, &ActionPermissionLevel::User, &state.database_pool).await?;
    let authenticated_principal = get_authenticated_principal(authenticated_user.as_ref(), authenticated_app.as_ref())?;
    verify_principal_permissions(&authenticated_principal, &create_field_values_action, &resource_hierarchy, &http_transaction, &ActionPermissionLevel::User, &state.database_pool).await?;

    // Verify the field is a part of the same project.
    let field = get_field_by_id(&field_value_properties_json.field_id, &http_transaction, &state.database_pool).await?;
    if field.parent_project_id != target_item.parent_project_id {

      let http_error = HTTPError::UnprocessableEntity(Some("The specified field is not a part of the same project as the item.".to_string()));
      ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
      return Err(http_error)

    }

    // Create the field value.
    ServerLogEntry::trace(&format!("Creating field value for item {}...", item_id), Some(&http_transaction.id), &state.database_pool).await.ok();
    let field_value = match FieldValue::create(&InitialFieldValueProperties {
      field_id: field_value_properties_json.field_id,
      parent_resource_type: FieldValueParentResourceType::Item,
      parent_item_id: Some(target_item.id),
      parent_field_id: None,
      value_type: field_value_properties_json.value_type,
      text_value: field_value_properties_json.text_value.clone(),
      number_value: field_value_properties_json.number_value,
      boolean_value: field_value_properties_json.boolean_value,
      timestamp_value: field_value_properties_json.timestamp_value,
      stakeholder_type: field_value_properties_json.stakeholder_type,
      stakeholder_user_id: field_value_properties_json.stakeholder_user_id,
      stakeholder_group_id: field_value_properties_json.stakeholder_group_id,
      stakeholder_app_id: field_value_properties_json.stakeholder_app_id,
    }, &state.database_pool).await {

      Ok(field_value) => field_value,

      Err(error) => {

        let http_error = HTTPError::InternalServerError(Some(format!("Failed to create field value: {:?}", error)));
        ServerLogEntry::from_http_error(&http_error, Some(&http_transaction.id), &state.database_pool).await.ok();
        return Err(http_error)

      }

    };

    let expiration_timestamp = get_action_log_entry_expiration_timestamp(&http_transaction, &state.database_pool).await?;
    ActionLogEntry::create(&InitialActionLogEntryProperties {
      action_id: create_field_values_action.id,
      http_transaction_id: Some(http_transaction.id),
      expiration_timestamp,
      actor_type: if let AuthenticatedPrincipal::User(_) = &authenticated_principal { ActionLogEntryActorType::User } else { ActionLogEntryActorType::App },
      actor_user_id: if let AuthenticatedPrincipal::User(user) = &authenticated_principal { Some(user.id.clone()) } else { None },
      actor_app_id: if let AuthenticatedPrincipal::App(app) = &authenticated_principal { Some(app.id.clone()) } else { None },
      target_resource_type: ActionLogEntryTargetResourceType::FieldValue,
      target_field_value_id: Some(field_value.id),
      ..Default::default()
    }, &state.database_pool).await.ok();
    ServerLogEntry::success(&format!("Successfully created field value {}.", field_value.id), Some(&http_transaction.id), &state.database_pool).await.ok();

    return Ok((StatusCode::CREATED, Json(field_value)));

  }

  pub fn get_router(state: AppState) -> Router<AppState> {

    let router = Router::<AppState>::new()
      .route("/items/{item_id}/field-values", axum::routing::get(handle_list_field_values_request))
      .route("/items/{item_id}/field-values", axum::routing::post(handle_create_field_value_request))
      .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_user))
      .layer(axum::middleware::from_fn_with_state(state.clone(), authentication_middleware::authenticate_app))
      .layer(axum::middleware::from_fn_with_state(state.clone(), http_transaction_middleware::create_http_transaction));
    return router;

  }
