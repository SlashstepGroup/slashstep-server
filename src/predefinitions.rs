use crate::resources::{ResourceError, action::{Action, ActionParentResourceType, InitialActionProperties}, role::{InitialRoleProperties, Role}};
use colored::Colorize;

pub async fn initialize_predefined_actions(database_pool: &deadpool_postgres::Pool) -> Result<Vec<Action>, ResourceError> {

  println!("{}", "Initializing predefined actions...".dimmed());

  let predefined_actions: Vec<InitialActionProperties> = vec![
    InitialActionProperties {
      name: "slashstep.accessPolicies.get".to_string(),
      display_name: "Get access policies".to_string(),
      description: "Get a specific access policy on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.list".to_string(),
      display_name: "List access policies".to_string(),
      description: "List all access policies on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.create".to_string(),
      display_name: "Create access policies".to_string(),
      description: "Create new access policy on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.update".to_string(),
      display_name: "Update access policies".to_string(),
      description: "Update access policies on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.delete".to_string(),
      display_name: "Delete access policies".to_string(),
      description: "Delete access policies on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actions.get".to_string(),
      display_name: "Get actions".to_string(),
      description: "Get specific access policies on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actions.list".to_string(),
      display_name: "List actions".to_string(),
      description: "List all actions on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actions.delete".to_string(),
      display_name: "Delete actions".to_string(),
      description: "Delete actions on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance 
    },
    InitialActionProperties {
      name: "slashstep.actions.update".to_string(),
      display_name: "Update actions".to_string(),
      description: "Update actions on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.get".to_string(),
      display_name: "Get action log entries".to_string(),
      description: "Get a specific action log entry on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.delete".to_string(),
      display_name: "Delete action log entries".to_string(),
      description: "Delete action log entries on a particular scope. This can be a dangerous action to grant permissions for, as it can affect auditing.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.list".to_string(),
      display_name: "List action log entries".to_string(),
      description: "List all action log entries on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.apps.get".to_string(),
      display_name: "Get apps".to_string(),
      description: "Get an app on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.apps.list".to_string(),
      display_name: "List apps".to_string(),
      description: "List all apps on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.apps.update".to_string(),
      display_name: "Update apps".to_string(),
      description: "Update apps on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.apps.delete".to_string(),
      display_name: "Delete apps".to_string(),
      description: "Delete apps on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.actions.create".to_string(),
      display_name: "Create actions".to_string(),
      description: "Create new actions on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.create".to_string(),
      display_name: "Create app credentials".to_string(),
      description: "Create new app credentials on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.get".to_string(),
      display_name: "Get app credentials".to_string(),
      description: "Get an app credential on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.list".to_string(),
      display_name: "List app credentials".to_string(),
      description: "List all app credentials on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizations.get".to_string(),
      display_name: "Get an app authorization".to_string(),
      description: "Get an app authorization on a particular scope.".to_string(),
      parent_app_id: None,
      parent_resource_type: ActionParentResourceType::Instance
    }
  ];

  let mut actions: Vec<Action> = Vec::new();

  for predefined_action in predefined_actions {

    // Make sure we didn't go through this action already.
    let mut should_continue = false;
    for action in actions.iter() {

      if action.name == predefined_action.name {

        println!("{}", format!("Skipping predefined action \"{}\" because it already exists.", predefined_action.name).yellow());
        should_continue = true;

      }

    }

    if should_continue {

      continue;

    }

    // Create the action, but if it already exists, add it to the list of actions.
    let action = match Action::create(&predefined_action, database_pool).await {

      Ok(action) => action,

      Err(error) => {

        match error {

          ResourceError::ConflictError(_) => {

            let action = Action::get_by_name(&predefined_action.name, database_pool).await?;

            action

          },

          _ => return Err(error)

        }

      }

    };
    actions.push(action);

  }

  println!("{}", format!("Successfully initialized {} predefined actions.", actions.len()).blue());

  return Ok(actions);

}

pub async fn initialize_predefined_roles(database_pool: &deadpool_postgres::Pool) -> Result<Vec<Role>, ResourceError> {

  println!("{}", "Initializing predefined roles...".dimmed());

  let predefined_roles: Vec<InitialRoleProperties> = vec![
    InitialRoleProperties {
      name: "anonymous-users".to_string(),
      display_name: "Anonymous Users".to_string(),
      description: Some("Users who have not logged in. Registered users should not be assigned this role.".to_string()),
      parent_resource_type: crate::resources::role::RoleParentResourceType::Instance,
      parent_workspace_id: None,
      parent_project_id: None,
      parent_group_id: None
    }
  ];

  let mut roles: Vec<Role> = Vec::new();

  for predefined_role in predefined_roles {

    // Make sure we didn't go through this role already.
    let mut should_continue = false;
    for role in roles.iter() {

      if role.name == predefined_role.name {

        println!("{}", format!("Skipping predefined role \"{}\" because it already exists.", predefined_role.name).yellow());
        should_continue = true;

      }

    }

    if should_continue {

      continue;

    }

    // Create the role, but if it already exists, add it to the list of roles.
    let role = Role::create(&predefined_role, database_pool).await?;
    roles.push(role);

  }

  println!("{}", format!("Successfully initialized {} predefined roles.", roles.len()).blue());

  return Ok(roles);

}
