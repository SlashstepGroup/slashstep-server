use slashstep_server::resources::field::FieldValueType;
use uuid::Uuid;

use slashstep_server::resources::field_value::{
    DEFAULT_RESOURCE_LIST_LIMIT, FieldValue, GET_RESOURCE_ACTION_NAME, InitialFieldValueProperties,
};
use slashstep_server::resources::{
    ResourceError, ResourceType,
    access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties},
    action::{Action, DEFAULT_ACTION_LIST_LIMIT},
};

use crate::test_utilities::{
    integration_test_environment::IntegrationTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};

fn assert_fields_are_equal(field_value_1: &FieldValue, field_value_2: &FieldValue) {
    assert_eq!(field_value_1.id, field_value_2.id);
    assert_eq!(field_value_1.field_id, field_value_2.field_id);
    assert_eq!(field_value_1.value_type, field_value_2.value_type);
    assert_eq!(field_value_1.text_value, field_value_2.text_value);
    assert_eq!(field_value_1.number_value, field_value_2.number_value);
    assert_eq!(field_value_1.boolean_value, field_value_2.boolean_value);
    assert_eq!(field_value_1.timestamp_value, field_value_2.timestamp_value);
    assert_eq!(
        field_value_1.stakeholder_type,
        field_value_2.stakeholder_type
    );
    assert_eq!(
        field_value_1.stakeholder_user_id,
        field_value_2.stakeholder_user_id
    );
    assert_eq!(
        field_value_1.stakeholder_group_id,
        field_value_2.stakeholder_group_id
    );
    assert_eq!(
        field_value_1.stakeholder_app_id,
        field_value_2.stakeholder_app_id
    );
}

fn assert_field_is_equal_to_initial_properties(
    field_value: &FieldValue,
    initial_properties: &InitialFieldValueProperties,
) {
    assert_eq!(field_value.field_id, initial_properties.field_id);
    assert_eq!(field_value.value_type, initial_properties.value_type);
    assert_eq!(field_value.text_value, initial_properties.text_value);
    assert_eq!(field_value.number_value, initial_properties.number_value);
    assert_eq!(field_value.boolean_value, initial_properties.boolean_value);
    assert_eq!(
        field_value.timestamp_value,
        initial_properties.timestamp_value
    );
    assert_eq!(
        field_value.stakeholder_type,
        initial_properties.stakeholder_type
    );
    assert_eq!(
        field_value.stakeholder_user_id,
        initial_properties.stakeholder_user_id
    );
    assert_eq!(
        field_value.stakeholder_group_id,
        initial_properties.stakeholder_group_id
    );
    assert_eq!(
        field_value.stakeholder_app_id,
        initial_properties.stakeholder_app_id
    );
}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    let initial_resource_count =
        FieldValue::count("", &test_environment.database_pool, None, None).await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut created_resources: Vec<FieldValue> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_field_value().await?;
        created_resources.push(resource);
    }

    let retrieved_resource_count =
        FieldValue::count("", &test_environment.database_pool, None, None).await?;

    assert_eq!(
        retrieved_resource_count,
        MAXIMUM_RESOURCE_COUNT + initial_resource_count
    );

    return Ok(());
}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    // Create the access policy.
    let field = test_environment.create_random_field(None).await?;
    let field_properties = InitialFieldValueProperties {
        field_id: field.id,
        value_type: FieldValueType::Text,
        text_value: Some(Uuid::now_v7().to_string()),
        ..Default::default()
    };
    let field_value =
        FieldValue::create(&field_properties, &test_environment.database_pool).await?;

    // Ensure that all the properties were set correctly.
    assert_field_is_equal_to_initial_properties(&field_value, &field_properties);

    return Ok(());
}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {
    // Create the access policy.
    let test_environment = IntegrationTestEnvironment::new().await?;
    let created_field_value = test_environment.create_random_field_value().await?;

    created_field_value
        .delete(&test_environment.database_pool)
        .await?;

    // Ensure that the access policy is no longer in the database.
    match FieldValue::get_by_id(&created_field_value.id, &test_environment.database_pool).await {
        Ok(_) => panic!("Expected a resource not found error."),

        Err(error) => match error {
            ResourceError::NotFoundError(_) => {}

            error => return Err(TestSlashstepServerError::ResourceError(error)),
        },
    };

    return Ok(());
}

#[tokio::test]
async fn verify_get_resource_by_id() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let created_field_value = test_environment.create_random_field_value().await?;
    let retrieved_resource =
        FieldValue::get_by_id(&created_field_value.id, &test_environment.database_pool).await?;
    assert_fields_are_equal(&created_field_value, &retrieved_resource);

    return Ok(());
}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut fields: Vec<FieldValue> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let field_value = test_environment.create_random_field_value().await?;
        fields.push(field_value);
    }

    let retrieved_resources =
        FieldValue::list("", &test_environment.database_pool, None, None).await?;

    assert_eq!(
        retrieved_resources.len(),
        DEFAULT_ACTION_LIST_LIMIT as usize
    );

    return Ok(());
}

/// Verifies that a list of resources can be retrieved with a query.
#[tokio::test]
async fn verify_list_resources_with_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i32 = 5;
    let mut created_resources: Vec<FieldValue> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_field_value().await?;
        created_resources.push(resource);
    }

    let query = format!("id = \"{}\"", created_resources[0].id);
    let retrieved_resources =
        FieldValue::list(&query, &test_environment.database_pool, None, None).await?;

    let created_resources_with_specific_id: Vec<&FieldValue> = created_resources
        .iter()
        .filter(|field_value| field_value.id == created_resources[0].id)
        .collect();
    assert_eq!(
        created_resources_with_specific_id.len(),
        retrieved_resources.len()
    );
    for i in 0..created_resources_with_specific_id.len() {
        let created_resource = &created_resources_with_specific_id[i];
        let retrieved_resource = &retrieved_resources[i];

        assert_fields_are_equal(created_resource, retrieved_resource);
    }

    return Ok(());
}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i32 = 25;
    let mut created_resources: Vec<FieldValue> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let field_value = test_environment.create_random_field_value().await?;
        created_resources.push(field_value);
    }

    let retrieved_resources =
        FieldValue::list("", &test_environment.database_pool, None, None).await?;

    for created_field_value in &created_resources {
        let retrieved_field_value_option = retrieved_resources
            .iter()
            .find(|retrieved_field_value| retrieved_field_value.id == created_field_value.id);
        assert!(retrieved_field_value_option.is_some());
    }

    return Ok(());
}

/// Verifies that a list of resources can be retrieved without a query.
#[tokio::test]
async fn verify_list_resources_without_query_and_filter_based_on_requestor_permissions()
-> Result<(), TestSlashstepServerError> {
    // Make sure there are at least two actions.
    let test_environment = IntegrationTestEnvironment::new().await?;

    const MINIMUM_RESOURCE_COUNT: i32 = 2;
    let mut current_resources =
        FieldValue::list("", &test_environment.database_pool, None, None).await?;
    if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {
        let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
        for _ in 0..remaining_action_count {
            let field_value = test_environment.create_random_field_value().await?;
            current_resources.push(field_value);
        }
    }

    // Get the "fields.get" action one time.
    let user = test_environment.create_random_user(None).await?;
    let get_fields_action =
        Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

    // Grant access to the "fields.get" action to the user for half of the actions.
    let allowed_resource_count = current_resources.len() / 2;
    let mut allowed_resources = Vec::new();
    for index in 0..allowed_resource_count {
        let scoped_field_value = &current_resources[index];

        AccessPolicy::create(
            &InitialAccessPolicyProperties {
                action_id: get_fields_action.id.clone(),
                permission_level: slashstep_server::resources::access_policy::PermissionLevel::User,
                principal_type:
                    slashstep_server::resources::access_policy::AccessPolicyPrincipalType::User,
                principal_user_id: Some(user.id.clone()),
                scoped_resource_type: ResourceType::FieldValue,
                scoped_field_value_id: Some(scoped_field_value.id.clone()),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

        allowed_resources.push(scoped_field_value.clone());
    }

    // Make sure the user only sees the allowed actions.
    let retrieved_resources = FieldValue::list(
        "",
        &test_environment.database_pool,
        Some(&AccessPolicyPrincipalType::User),
        Some(&user.id),
    )
    .await?;

    assert_eq!(allowed_resources.len(), retrieved_resources.len());
    for allowed_resource in allowed_resources {
        let retrieved_resource = &retrieved_resources
            .iter()
            .find(|action| action.id == allowed_resource.id)
            .expect("Expected a retrieved resource with the same ID.");

        assert_fields_are_equal(&allowed_resource, retrieved_resource);
    }

    return Ok(());
}
