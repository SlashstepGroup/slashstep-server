use uuid::Uuid;

use slashstep_server::resources::webhook::{
    DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, InitialWebhookProperties, Webhook,
};
use slashstep_server::resources::{
    ResourceError, ResourceType,
    access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties},
    action::{Action, DEFAULT_ACTION_LIST_LIMIT},
    webhook::WebhookParentResourceType,
};

use crate::test_utilities::{
    integration_test_environment::IntegrationTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};

fn assert_webhooks_are_equal(webhook_1: &Webhook, webhook_2: &Webhook) {
    assert_eq!(webhook_1.id, webhook_2.id);
    assert_eq!(webhook_1.display_name, webhook_2.display_name);
    assert_eq!(webhook_1.url, webhook_2.url);
    assert_eq!(webhook_1.get_hashed_secret(), webhook_2.get_hashed_secret());
    assert_eq!(webhook_1.is_enabled, webhook_2.is_enabled);
    assert_eq!(
        webhook_1.parent_resource_type,
        webhook_2.parent_resource_type
    );
    assert_eq!(webhook_1.parent_app_id, webhook_2.parent_app_id);
    assert_eq!(webhook_1.parent_group_id, webhook_2.parent_group_id);
    assert_eq!(webhook_1.parent_project_id, webhook_2.parent_project_id);
    assert_eq!(webhook_1.parent_user_id, webhook_2.parent_user_id);
    assert_eq!(webhook_1.parent_workspace_id, webhook_2.parent_workspace_id);
}

fn assert_webhook_is_equal_to_initial_properties(
    webhook: &Webhook,
    initial_properties: &InitialWebhookProperties,
) {
    assert_eq!(webhook.display_name, initial_properties.display_name);
    assert_eq!(webhook.url, initial_properties.url);
    assert_eq!(
        webhook.get_hashed_secret(),
        initial_properties.hashed_secret
    );
    assert_eq!(
        webhook.parent_resource_type,
        initial_properties.parent_resource_type
    );
    assert_eq!(webhook.parent_app_id, initial_properties.parent_app_id);
    assert_eq!(webhook.parent_group_id, initial_properties.parent_group_id);
    assert_eq!(
        webhook.parent_project_id,
        initial_properties.parent_project_id
    );
    assert_eq!(webhook.parent_user_id, initial_properties.parent_user_id);
    assert_eq!(
        webhook.parent_workspace_id,
        initial_properties.parent_workspace_id
    );
}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    let initial_resource_count =
        Webhook::count("", &test_environment.database_pool, None, None).await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut created_resources: Vec<Webhook> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_webhook().await?;
        created_resources.push(resource);
    }

    let retrieved_resource_count =
        Webhook::count("", &test_environment.database_pool, None, None).await?;

    assert_eq!(retrieved_resource_count, MAXIMUM_RESOURCE_COUNT + initial_resource_count);

    return Ok(());
}

#[tokio::test]
async fn verify_creation() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;

    let webhook_properties = InitialWebhookProperties {
        display_name: Uuid::now_v7().to_string(),
        url: "https://example.internal".to_string(),
        parent_resource_type: WebhookParentResourceType::Server,
        is_enabled: true,
        ..Default::default()
    };

    let webhook = Webhook::create(&webhook_properties, &test_environment.database_pool).await?;
    assert_webhook_is_equal_to_initial_properties(&webhook, &webhook_properties);

    return Ok(());
}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {
    // Create the access policy.
    let test_environment = IntegrationTestEnvironment::new().await?;
    let created_webhook = test_environment.create_random_webhook().await?;

    created_webhook
        .delete(&test_environment.database_pool)
        .await?;

    // Ensure that the access policy is no longer in the database.
    match Webhook::get_by_id(&created_webhook.id, &test_environment.database_pool).await {
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

    let created_webhook = test_environment.create_random_webhook().await?;
    let retrieved_resource =
        Webhook::get_by_id(&created_webhook.id, &test_environment.database_pool).await?;
    assert_webhooks_are_equal(&created_webhook, &retrieved_resource);

    return Ok(());
}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut webhooks: Vec<Webhook> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let webhook = test_environment.create_random_webhook().await?;
        webhooks.push(webhook);
    }

    let retrieved_resources =
        Webhook::list("", &test_environment.database_pool, None, None).await?;

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
    let mut created_resources: Vec<Webhook> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_webhook().await?;
        created_resources.push(resource);
    }

    let query = format!("id = \"{}\"", created_resources[0].id);
    let retrieved_resources =
        Webhook::list(&query, &test_environment.database_pool, None, None).await?;

    let created_resources_with_specific_id: Vec<&Webhook> = created_resources
        .iter()
        .filter(|webhook| webhook.id == created_resources[0].id)
        .collect();
    assert_eq!(
        created_resources_with_specific_id.len(),
        retrieved_resources.len()
    );
    for i in 0..created_resources_with_specific_id.len() {
        let created_resource = &created_resources_with_specific_id[i];
        let retrieved_resource = &retrieved_resources[i];

        assert_webhooks_are_equal(created_resource, retrieved_resource);
    }

    return Ok(());
}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i32 = 25;
    let mut created_resources: Vec<Webhook> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let webhook = test_environment.create_random_webhook().await?;
        created_resources.push(webhook);
    }

    let retrieved_resources =
        Webhook::list("", &test_environment.database_pool, None, None).await?;

    for created_webhook in &created_resources {
        let retrieved_webhook_option = retrieved_resources
            .iter()
            .find(|retrieved_webhook| retrieved_webhook.id == created_webhook.id);
        assert!(retrieved_webhook_option.is_some());
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
        Webhook::list("", &test_environment.database_pool, None, None).await?;
    if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {
        let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
        for _ in 0..remaining_action_count {
            let webhook = test_environment.create_random_webhook().await?;
            current_resources.push(webhook);
        }
    }

    // Get the "webhooks.get" action one time.
    let user = test_environment.create_random_user(None).await?;
    let get_webhooks_action =
        Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

    // Grant access to the "webhooks.get" action to the user for half of the actions.
    let allowed_resource_count = current_resources.len() / 2;
    let mut allowed_resources = Vec::new();
    for index in 0..allowed_resource_count {
        let scoped_webhook = &current_resources[index];

        AccessPolicy::create(
            &InitialAccessPolicyProperties {
                action_id: get_webhooks_action.id.clone(),
                permission_level: slashstep_server::resources::access_policy::PermissionLevel::User,
                principal_type:
                    slashstep_server::resources::access_policy::AccessPolicyPrincipalType::User,
                principal_user_id: Some(user.id.clone()),
                scoped_resource_type: ResourceType::Webhook,
                scoped_webhook_id: Some(scoped_webhook.id.clone()),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

        allowed_resources.push(scoped_webhook.clone());
    }

    // Make sure the user only sees the allowed actions.
    let retrieved_resources = Webhook::list(
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

        assert_webhooks_are_equal(&allowed_resource, retrieved_resource);
    }

    return Ok(());
}
