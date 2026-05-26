use uuid::Uuid;

use slashstep_server::resources::group::{
    DEFAULT_RESOURCE_LIST_LIMIT, GET_RESOURCE_ACTION_NAME, Group, InitialGroupProperties,
};
use slashstep_server::resources::{
    ResourceError, ResourceType,
    access_policy::{AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties},
    action::{Action, DEFAULT_ACTION_LIST_LIMIT},
    group::GroupParentResourceType,
};

use crate::test_utilities::{
    integration_test_environment::IntegrationTestEnvironment,
    test_slashstep_server_error::TestSlashstepServerError,
};

fn assert_groups_are_equal(group_1: &Group, group_2: &Group) {
    assert_eq!(group_1.id, group_2.id);
    assert_eq!(group_1.name, group_2.name);
    assert_eq!(group_1.display_name, group_2.display_name);
    assert_eq!(group_1.description, group_2.description);
}

fn assert_group_is_equal_to_initial_properties(
    group: &Group,
    initial_properties: &InitialGroupProperties,
) {
    assert_eq!(group.name, initial_properties.name);
    assert_eq!(group.display_name, initial_properties.display_name);
    assert_eq!(group.description, initial_properties.description);
}

#[tokio::test]
async fn verify_count() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    let initial_resource_count =
        Group::count("", &test_environment.database_pool, None, None).await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut created_resources: Vec<Group> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_group().await?;
        created_resources.push(resource);
    }

    let retrieved_resource_count =
        Group::count("", &test_environment.database_pool, None, None).await?;

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
    let group_properties = InitialGroupProperties {
        name: Uuid::now_v7().to_string(),
        display_name: Uuid::now_v7().to_string(),
        description: Some(Uuid::now_v7().to_string()),
        parent_resource_type: GroupParentResourceType::Server,
        parent_group_id: None,
        predefined_group_type: None,
    };
    let group = Group::create(&group_properties, &test_environment.database_pool).await?;

    // Ensure that all the properties were set correctly.
    assert_group_is_equal_to_initial_properties(&group, &group_properties);

    return Ok(());
}

#[tokio::test]
async fn verify_deletion() -> Result<(), TestSlashstepServerError> {
    // Create the access policy.
    let test_environment = IntegrationTestEnvironment::new().await?;
    let created_group = test_environment.create_random_group().await?;

    created_group
        .delete(&test_environment.database_pool)
        .await?;

    // Ensure that the access policy is no longer in the database.
    match Group::get_by_id(&created_group.id, &test_environment.database_pool).await {
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

    let created_group = test_environment.create_random_group().await?;
    let retrieved_resource =
        Group::get_by_id(&created_group.id, &test_environment.database_pool).await?;
    assert_groups_are_equal(&created_group, &retrieved_resource);

    return Ok(());
}

/// Verifies that the implementation can return up to a maximum number of resources by default.
#[tokio::test]
async fn verify_list_resources_with_default_limit() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i64 = DEFAULT_RESOURCE_LIST_LIMIT + 1;
    let mut groups: Vec<Group> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let group = test_environment.create_random_group().await?;
        groups.push(group);
    }

    let retrieved_resources = Group::list("", &test_environment.database_pool, None, None).await?;

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
    let mut created_resources: Vec<Group> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let resource = test_environment.create_random_group().await?;
        created_resources.push(resource);
    }

    let query = format!("id = \"{}\"", created_resources[0].id);
    let retrieved_resources =
        Group::list(&query, &test_environment.database_pool, None, None).await?;

    let created_resources_with_specific_id: Vec<&Group> = created_resources
        .iter()
        .filter(|group| group.id == created_resources[0].id)
        .collect();
    assert_eq!(
        created_resources_with_specific_id.len(),
        retrieved_resources.len()
    );
    for i in 0..created_resources_with_specific_id.len() {
        let created_resource = &created_resources_with_specific_id[i];
        let retrieved_resource = &retrieved_resources[i];

        assert_groups_are_equal(created_resource, retrieved_resource);
    }

    return Ok(());
}

#[tokio::test]
async fn verify_list_resources_without_query() -> Result<(), TestSlashstepServerError> {
    let test_environment = IntegrationTestEnvironment::new().await?;
    const MAXIMUM_RESOURCE_COUNT: i32 = 25;
    let mut created_resources: Vec<Group> = Vec::new();
    for _ in 0..MAXIMUM_RESOURCE_COUNT {
        let group = test_environment.create_random_group().await?;
        created_resources.push(group);
    }

    let retrieved_resources = Group::list("", &test_environment.database_pool, None, None).await?;

    for created_group in &created_resources {
        let retrieved_group_option = retrieved_resources
            .iter()
            .find(|retrieved_group| retrieved_group.id == created_group.id);
        assert!(retrieved_group_option.is_some());
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
        Group::list("", &test_environment.database_pool, None, None).await?;
    if current_resources.len() < MINIMUM_RESOURCE_COUNT as usize {
        let remaining_action_count = MINIMUM_RESOURCE_COUNT - current_resources.len() as i32;
        for _ in 0..remaining_action_count {
            let group = test_environment.create_random_group().await?;
            current_resources.push(group);
        }
    }

    // Get the "groups.get" action one time.
    let user = test_environment.create_random_user(None).await?;
    let get_groups_action =
        Action::get_by_name(GET_RESOURCE_ACTION_NAME, &test_environment.database_pool).await?;

    // Grant access to the "groups.get" action to the user for half of the actions.
    let allowed_resource_count = current_resources.len() / 2;
    let mut allowed_resources = Vec::new();
    for index in 0..allowed_resource_count {
        let scoped_group = &current_resources[index];

        AccessPolicy::create(
            &InitialAccessPolicyProperties {
                action_id: get_groups_action.id.clone(),
                permission_level: slashstep_server::resources::access_policy::PermissionLevel::User,
                principal_type:
                    slashstep_server::resources::access_policy::AccessPolicyPrincipalType::User,
                principal_user_id: Some(user.id.clone()),
                scoped_resource_type: ResourceType::Group,
                scoped_group_id: Some(scoped_group.id.clone()),
                ..Default::default()
            },
            &test_environment.database_pool,
        )
        .await?;

        allowed_resources.push(scoped_group.clone());
    }

    // Make sure the user only sees the allowed actions.
    let retrieved_resources = Group::list(
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

        assert_groups_are_equal(&allowed_resource, retrieved_resource);
    }

    return Ok(());
}
