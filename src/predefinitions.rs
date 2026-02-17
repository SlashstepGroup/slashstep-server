use crate::resources::{ResourceError, action::{Action, InitialActionProperties}, role::{InitialRoleProperties, Role}};
use colored::Colorize;

pub async fn initialize_predefined_actions(database_pool: &deadpool_postgres::Pool) -> Result<Vec<Action>, ResourceError> {

  println!("{}", "Initializing predefined actions...".dimmed());

  let predefined_actions: Vec<InitialActionProperties> = vec![
    InitialActionProperties {
      name: "slashstep.accessPolicies.get".to_string(),
      display_name: "Get access policies".to_string(),
      description: "Get a specific access policy on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.list".to_string(),
      display_name: "List access policies".to_string(),
      description: "List all access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.create".to_string(),
      display_name: "Create access policies".to_string(),
      description: "Create new access policy on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.update".to_string(),
      display_name: "Update access policies".to_string(),
      description: "Update access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.accessPolicies.delete".to_string(),
      display_name: "Delete access policies".to_string(),
      description: "Delete access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actions.get".to_string(),
      display_name: "Get actions".to_string(),
      description: "Get specific access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actions.list".to_string(),
      display_name: "List actions".to_string(),
      description: "List all actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actions.delete".to_string(),
      display_name: "Delete actions".to_string(),
      description: "Delete actions on a particular scope.".to_string(),
      ..Default::default() 
    },
    InitialActionProperties {
      name: "slashstep.actions.update".to_string(),
      display_name: "Update actions".to_string(),
      description: "Update actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.get".to_string(),
      display_name: "Get action log entries".to_string(),
      description: "Get a specific action log entry on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.delete".to_string(),
      display_name: "Delete action log entries".to_string(),
      description: "Delete action log entries on a particular scope. This can be a dangerous action to grant permissions for, as it can affect auditing.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actionLogEntries.list".to_string(),
      display_name: "List action log entries".to_string(),
      description: "List all action log entries on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.apps.get".to_string(),
      display_name: "Get apps".to_string(),
      description: "Get an app on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.apps.list".to_string(),
      display_name: "List apps".to_string(),
      description: "List all apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.apps.update".to_string(),
      display_name: "Update apps".to_string(),
      description: "Update apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.apps.delete".to_string(),
      display_name: "Delete apps".to_string(),
      description: "Delete apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.apps.authorize".to_string(),
      display_name: "Authorize apps".to_string(),
      description: "Authorize apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.oauthAuthorizations.create".to_string(),
      display_name: "Create OAuth authorizations".to_string(),
      description: "Create OAuth authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.actions.create".to_string(),
      display_name: "Create actions".to_string(),
      description: "Create new actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.create".to_string(),
      display_name: "Create app credentials".to_string(),
      description: "Create new app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.get".to_string(),
      display_name: "Get app credentials".to_string(),
      description: "Get an app credential on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.list".to_string(),
      display_name: "List app credentials".to_string(),
      description: "List all app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appCredentials.delete".to_string(),
      display_name: "Delete app credentials".to_string(),
      description: "Delete app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizations.get".to_string(),
      display_name: "Get an app authorization".to_string(),
      description: "Get an app authorization on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizations.list".to_string(),
      display_name: "List app authorizations".to_string(),
      description: "List all app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizations.create".to_string(),
      display_name: "Create app authorizations".to_string(),
      description: "Create new app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizations.delete".to_string(),
      display_name: "Delete app authorizations".to_string(),
      description: "Delete app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizationCredentials.get".to_string(),
      display_name: "Get app authorization credentials".to_string(),
      description: "Get an app authorization credential on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizationCredentials.list".to_string(),
      display_name: "List app authorization credentials".to_string(),
      description: "List app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.appAuthorizationCredentials.create".to_string(),
      display_name: "Create app authorization credentials".to_string(),
      description: "Create new app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.appAuthorizationCredentials.delete".to_string(),
      display_name: "Delete app authorization credentials".to_string(),
      description: "Delete app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fields.get".to_string(),
      display_name: "Get fields".to_string(),
      description: "Get a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fields.list".to_string(),
      display_name: "List fields".to_string(),
      description: "List all fields on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fields.create".to_string(),
      display_name: "Create field".to_string(),
      description: "Create a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fields.update".to_string(),
      display_name: "Update field".to_string(),
      description: "Update a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fields.delete".to_string(),
      display_name: "Delete field".to_string(),
      description: "Delete a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldChoices.get".to_string(),
      display_name: "Get field choices".to_string(),
      description: "Get a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldChoices.list".to_string(),
      display_name: "List field choices".to_string(),
      description: "List all field choices on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldChoices.create".to_string(),
      display_name: "Create field choices".to_string(),
      description: "Create a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldChoices.update".to_string(),
      display_name: "Update field choice".to_string(),
      description: "Update a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldChoices.delete".to_string(),
      display_name: "Delete field choice".to_string(),
      description: "Delete a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldValues.get".to_string(),
      display_name: "Get field values".to_string(),
      description: "Get a specific field value on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldValues.list".to_string(),
      display_name: "List field values".to_string(),
      description: "List all field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldValues.create".to_string(),
      display_name: "Create field values".to_string(),
      description: "Create new field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldValues.update".to_string(),
      display_name: "Update field values".to_string(),
      description: "Update field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.fieldValues.delete".to_string(),
      display_name: "Delete field values".to_string(),
      description: "Delete field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.groups.get".to_string(),
      display_name: "Get groups".to_string(),
      description: "Get a specific group on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.groups.list".to_string(),
      display_name: "List groups".to_string(),
      description: "List all groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.groups.create".to_string(),
      display_name: "Create groups".to_string(),
      description: "Create new groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.groups.update".to_string(),
      display_name: "Update groups".to_string(),
      description: "Update groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.groups.delete".to_string(),
      display_name: "Delete groups".to_string(),
      description: "Delete groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.httpTransactions.get".to_string(),
      display_name: "Get HTTP transactions".to_string(),
      description: "Get a specific HTTP transaction on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.httpTransactions.list".to_string(),
      display_name: "List HTTP transactions".to_string(),
      description: "List all HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.httpTransactions.create".to_string(),
      display_name: "Create HTTP transactions".to_string(),
      description: "Create new HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.httpTransactions.update".to_string(),
      display_name: "Update HTTP transactions".to_string(),
      description: "Update HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.httpTransactions.delete".to_string(),
      display_name: "Delete HTTP transactions".to_string(),
      description: "Delete HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.items.get".to_string(),
      display_name: "Get items".to_string(),
      description: "Get a specific item on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.items.list".to_string(),
      display_name: "List items".to_string(),
      description: "List all items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.items.create".to_string(),
      display_name: "Create items".to_string(),
      description: "Create new items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.items.update".to_string(),
      display_name: "Update items".to_string(),
      description: "Update items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.items.delete".to_string(),
      display_name: "Delete items".to_string(),
      description: "Delete items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnections.get".to_string(),
      display_name: "Get item connections".to_string(),
      description: "Get a specific item connection on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnections.list".to_string(),
      display_name: "List item connections".to_string(),
      description: "List all item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnections.create".to_string(),
      display_name: "Create item connections".to_string(),
      description: "Create new item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnections.update".to_string(),
      display_name: "Update item connections".to_string(),
      description: "Update item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnections.delete".to_string(),
      display_name: "Delete item connections".to_string(),
      description: "Delete item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnectionTypes.get".to_string(),
      display_name: "Get item connection types".to_string(),
      description: "Get a specific item connection type on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnectionTypes.list".to_string(),
      display_name: "List item connection types".to_string(),
      description: "List all item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnectionTypes.create".to_string(),
      display_name: "Create item connection types".to_string(),
      description: "Create new item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnectionTypes.update".to_string(),
      display_name: "Update item connection types".to_string(),
      description: "Update item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.itemConnectionTypes.delete".to_string(),
      display_name: "Delete item connection types".to_string(),
      description: "Delete item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.memberships.get".to_string(),
      display_name: "Get memberships".to_string(),
      description: "Get a specific membership on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.memberships.list".to_string(),
      display_name: "List memberships".to_string(),
      description: "List all memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.memberships.create".to_string(),
      display_name: "Create memberships".to_string(),
      description: "Create new memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "slashstep.memberships.delete".to_string(),
      display_name: "Delete memberships".to_string(),
      description: "Delete memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.milestones.get".to_string(),
      display_name: "Get milestones".to_string(),
      description: "Get a specific milestone on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.milestones.list".to_string(),
      display_name: "List milestones".to_string(),
      description: "List all milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.milestones.create".to_string(),
      display_name: "Create milestones".to_string(),
      description: "Create new milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.milestones.delete".to_string(),
      display_name: "Delete milestones".to_string(),
      description: "Delete milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.milestones.update".to_string(),
      display_name: "Update milestones".to_string(),
      description: "Update milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.projects.get".to_string(),
      display_name: "Get projects".to_string(),
      description: "Get a specific project on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.projects.list".to_string(),
      display_name: "List projects".to_string(),
      description: "List all projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.projects.create".to_string(),
      display_name: "Create projects".to_string(),
      description: "Create new projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.projects.update".to_string(),
      display_name: "Update projects".to_string(),
      description: "Update projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.projects.delete".to_string(),
      display_name: "Delete projects".to_string(),
      description: "Delete projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.roles.get".to_string(),
      display_name: "Get roles".to_string(),
      description: "Get roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.roles.list".to_string(),
      display_name: "List roles".to_string(),
      description: "List roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.roles.create".to_string(),
      display_name: "Create roles".to_string(),
      description: "Create roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.roles.update".to_string(),
      display_name: "Update roles".to_string(),
      description: "Update roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.roles.delete".to_string(),
      display_name: "Delete roles".to_string(),
      description: "Delete roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.serverLogEntries.get".to_string(),
      display_name: "Get server log entries".to_string(),
      description: "Get a specific server log entry on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.serverLogEntries.list".to_string(),
      display_name: "List server log entries".to_string(),
      description: "List all server log entries on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.serverLogEntries.delete".to_string(),
      display_name: "Delete server log entries".to_string(),
      description: "Delete server log entries on a particular scope. This can be a dangerous action to grant permissions for, as it can affect auditing.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.sessions.get".to_string(),
      display_name: "Get sessions".to_string(),
      description: "Get a specific session on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.sessions.list".to_string(),
      display_name: "List sessions".to_string(),
      description: "List all sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.sessions.create".to_string(),
      display_name: "Create sessions".to_string(),
      description: "Create sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.sessions.delete".to_string(),
      display_name: "Delete sessions".to_string(),
      description: "Delete sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.users.get".to_string(),
      display_name: "Get users".to_string(),
      description: "Get a specific user on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.users.list".to_string(),
      display_name: "List users".to_string(),
      description: "List all users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.users.create".to_string(),
      display_name: "Create users".to_string(),
      description: "Create users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.users.update".to_string(),
      display_name: "Update users".to_string(),
      description: "Update users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.users.delete".to_string(),
      display_name: "Delete users".to_string(),
      description: "Delete users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.workspaces.get".to_string(),
      display_name: "Get workspaces".to_string(),
      description: "Get a specific workspace on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.workspaces.list".to_string(),
      display_name: "List workspaces".to_string(),
      description: "List all workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.workspaces.create".to_string(),
      display_name: "Create workspaces".to_string(),
      description: "Create new workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.workspaces.update".to_string(),
      display_name: "Update workspaces".to_string(),
      description: "Update workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "slashstep.workspaces.delete".to_string(),
      display_name: "Delete workspaces".to_string(),
      description: "Delete workspaces on a particular scope.".to_string(),
      ..Default::default()
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
      parent_resource_type: crate::resources::role::RoleParentResourceType::Server,
      ..Default::default()
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
