use crate::resources::{ResourceError, action::{Action, InitialActionProperties}, configuration::{Configuration, ConfigurationValueType, InitialConfigurationProperties}, role::{InitialRoleProperties, Role}};
use colored::Colorize;
use rust_decimal::Decimal;

pub async fn initialize_predefined_actions(database_pool: &deadpool_postgres::Pool) -> Result<Vec<Action>, ResourceError> {

  println!("{}", "Initializing predefined actions...".dimmed());

  let predefined_actions: Vec<InitialActionProperties> = vec![
    InitialActionProperties {
      name: "accessPolicies.get".to_string(),
      display_name: "Get access policies".to_string(),
      description: "Get a specific access policy on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "accessPolicies.list".to_string(),
      display_name: "List access policies".to_string(),
      description: "List all access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "accessPolicies.create".to_string(),
      display_name: "Create access policies".to_string(),
      description: "Create new access policy on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "accessPolicies.update".to_string(),
      display_name: "Update access policies".to_string(),
      description: "Update access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "accessPolicies.delete".to_string(),
      display_name: "Delete access policies".to_string(),
      description: "Delete access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actions.get".to_string(),
      display_name: "Get actions".to_string(),
      description: "Get specific access policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actions.list".to_string(),
      display_name: "List actions".to_string(),
      description: "List all actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actions.delete".to_string(),
      display_name: "Delete actions".to_string(),
      description: "Delete actions on a particular scope.".to_string(),
      ..Default::default() 
    },
    InitialActionProperties {
      name: "actions.update".to_string(),
      display_name: "Update actions".to_string(),
      description: "Update actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actionLogEntries.get".to_string(),
      display_name: "Get action log entries".to_string(),
      description: "Get a specific action log entry on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actionLogEntries.delete".to_string(),
      display_name: "Delete action log entries".to_string(),
      description: "Delete action log entries on a particular scope. This can be a dangerous action to grant permissions for, as it can affect auditing.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actionLogEntries.list".to_string(),
      display_name: "List action log entries".to_string(),
      description: "List all action log entries on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.get".to_string(),
      display_name: "Get apps".to_string(),
      description: "Get an app on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.list".to_string(),
      display_name: "List apps".to_string(),
      description: "List all apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.create".to_string(),
      display_name: "Create apps".to_string(),
      description: "Create new apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.update".to_string(),
      display_name: "Update apps".to_string(),
      description: "Update apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.delete".to_string(),
      display_name: "Delete apps".to_string(),
      description: "Delete apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "apps.authorize".to_string(),
      display_name: "Authorize apps".to_string(),
      description: "Authorize apps on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "oauthAuthorizations.create".to_string(),
      display_name: "Create OAuth authorizations".to_string(),
      description: "Create OAuth authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "actions.create".to_string(),
      display_name: "Create actions".to_string(),
      description: "Create new actions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appCredentials.create".to_string(),
      display_name: "Create app credentials".to_string(),
      description: "Create new app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appCredentials.get".to_string(),
      display_name: "Get app credentials".to_string(),
      description: "Get an app credential on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appCredentials.list".to_string(),
      display_name: "List app credentials".to_string(),
      description: "List all app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appCredentials.delete".to_string(),
      display_name: "Delete app credentials".to_string(),
      description: "Delete app credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizations.get".to_string(),
      display_name: "Get an app authorization".to_string(),
      description: "Get an app authorization on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizations.list".to_string(),
      display_name: "List app authorizations".to_string(),
      description: "List all app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizations.create".to_string(),
      display_name: "Create app authorizations".to_string(),
      description: "Create new app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizations.delete".to_string(),
      display_name: "Delete app authorizations".to_string(),
      description: "Delete app authorizations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizationCredentials.get".to_string(),
      display_name: "Get app authorization credentials".to_string(),
      description: "Get an app authorization credential on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizationCredentials.list".to_string(),
      display_name: "List app authorization credentials".to_string(),
      description: "List app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "appAuthorizationCredentials.create".to_string(),
      display_name: "Create app authorization credentials".to_string(),
      description: "Create new app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "appAuthorizationCredentials.delete".to_string(),
      display_name: "Delete app authorization credentials".to_string(),
      description: "Delete app authorization credentials on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurations.get".to_string(),
      display_name: "Get configurations".to_string(),
      description: "Get a specific configuration on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurations.list".to_string(),
      display_name: "List configurations".to_string(),
      description: "List all configurations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurations.create".to_string(),
      display_name: "Create configurations".to_string(),
      description: "Create new configurations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurations.update".to_string(),
      display_name: "Update configurations".to_string(),
      description: "Update configurations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurations.delete".to_string(),
      display_name: "Delete configurations".to_string(),
      description: "Delete configurations on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurationValues.get".to_string(),
      display_name: "Get configuration values".to_string(),
      description: "Get a specific configuration value on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurationValues.list".to_string(),
      display_name: "List configuration values".to_string(),
      description: "List all configuration values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurationValues.create".to_string(),
      display_name: "Create configuration values".to_string(),
      description: "Create new configuration values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurationValues.update".to_string(),
      display_name: "Update configuration values".to_string(),
      description: "Update configuration values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "configurationValues.delete".to_string(),
      display_name: "Delete configuration values".to_string(),
      description: "Delete configuration values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "delegationPolicies.get".to_string(),
      display_name: "Get delegation policies".to_string(),
      description: "Get a specific delegation policy on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "delegationPolicies.list".to_string(),
      display_name: "List delegation policies".to_string(),
      description: "List all delegation policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "delegationPolicies.create".to_string(),
      display_name: "Create delegation policies".to_string(),
      description: "Create new delegation policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "delegationPolicies.update".to_string(),
      display_name: "Update delegation policies".to_string(),
      description: "Update delegation policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "delegationPolicies.delete".to_string(),
      display_name: "Delete delegation policies".to_string(),
      description: "Delete delegation policies on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fields.get".to_string(),
      display_name: "Get fields".to_string(),
      description: "Get a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fields.list".to_string(),
      display_name: "List fields".to_string(),
      description: "List all fields on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fields.create".to_string(),
      display_name: "Create field".to_string(),
      description: "Create a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fields.update".to_string(),
      display_name: "Update field".to_string(),
      description: "Update a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fields.delete".to_string(),
      display_name: "Delete field".to_string(),
      description: "Delete a specific field on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldChoices.get".to_string(),
      display_name: "Get field choices".to_string(),
      description: "Get a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldChoices.list".to_string(),
      display_name: "List field choices".to_string(),
      description: "List all field choices on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldChoices.create".to_string(),
      display_name: "Create field choices".to_string(),
      description: "Create a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldChoices.update".to_string(),
      display_name: "Update field choice".to_string(),
      description: "Update a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldChoices.delete".to_string(),
      display_name: "Delete field choice".to_string(),
      description: "Delete a specific field choice on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldValues.get".to_string(),
      display_name: "Get field values".to_string(),
      description: "Get a specific field value on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldValues.list".to_string(),
      display_name: "List field values".to_string(),
      description: "List all field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldValues.create".to_string(),
      display_name: "Create field values".to_string(),
      description: "Create new field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldValues.update".to_string(),
      display_name: "Update field values".to_string(),
      description: "Update field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "fieldValues.delete".to_string(),
      display_name: "Delete field values".to_string(),
      description: "Delete field values on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "groups.get".to_string(),
      display_name: "Get groups".to_string(),
      description: "Get a specific group on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "groups.list".to_string(),
      display_name: "List groups".to_string(),
      description: "List all groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "groups.create".to_string(),
      display_name: "Create groups".to_string(),
      description: "Create new groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "groups.update".to_string(),
      display_name: "Update groups".to_string(),
      description: "Update groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "groups.delete".to_string(),
      display_name: "Delete groups".to_string(),
      description: "Delete groups on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "httpTransactions.get".to_string(),
      display_name: "Get HTTP transactions".to_string(),
      description: "Get a specific HTTP transaction on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "httpTransactions.list".to_string(),
      display_name: "List HTTP transactions".to_string(),
      description: "List all HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "httpTransactions.create".to_string(),
      display_name: "Create HTTP transactions".to_string(),
      description: "Create new HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "httpTransactions.update".to_string(),
      display_name: "Update HTTP transactions".to_string(),
      description: "Update HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "httpTransactions.delete".to_string(),
      display_name: "Delete HTTP transactions".to_string(),
      description: "Delete HTTP transactions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "items.get".to_string(),
      display_name: "Get items".to_string(),
      description: "Get a specific item on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "items.list".to_string(),
      display_name: "List items".to_string(),
      description: "List all items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "items.create".to_string(),
      display_name: "Create items".to_string(),
      description: "Create new items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "items.update".to_string(),
      display_name: "Update items".to_string(),
      description: "Update items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "items.delete".to_string(),
      display_name: "Delete items".to_string(),
      description: "Delete items on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnections.get".to_string(),
      display_name: "Get item connections".to_string(),
      description: "Get a specific item connection on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnections.list".to_string(),
      display_name: "List item connections".to_string(),
      description: "List all item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnections.create".to_string(),
      display_name: "Create item connections".to_string(),
      description: "Create new item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnections.update".to_string(),
      display_name: "Update item connections".to_string(),
      description: "Update item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnections.delete".to_string(),
      display_name: "Delete item connections".to_string(),
      description: "Delete item connections on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnectionTypes.get".to_string(),
      display_name: "Get item connection types".to_string(),
      description: "Get a specific item connection type on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnectionTypes.list".to_string(),
      display_name: "List item connection types".to_string(),
      description: "List all item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnectionTypes.create".to_string(),
      display_name: "Create item connection types".to_string(),
      description: "Create new item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnectionTypes.update".to_string(),
      display_name: "Update item connection types".to_string(),
      description: "Update item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "itemConnectionTypes.delete".to_string(),
      display_name: "Delete item connection types".to_string(),
      description: "Delete item connection types on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "memberships.get".to_string(),
      display_name: "Get memberships".to_string(),
      description: "Get a specific membership on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "memberships.list".to_string(),
      display_name: "List memberships".to_string(),
      description: "List all memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "memberships.create".to_string(),
      display_name: "Create memberships".to_string(),
      description: "Create new memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties { 
      name: "memberships.delete".to_string(),
      display_name: "Delete memberships".to_string(),
      description: "Delete memberships on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "milestones.get".to_string(),
      display_name: "Get milestones".to_string(),
      description: "Get a specific milestone on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "milestones.list".to_string(),
      display_name: "List milestones".to_string(),
      description: "List all milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "milestones.create".to_string(),
      display_name: "Create milestones".to_string(),
      description: "Create new milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "milestones.delete".to_string(),
      display_name: "Delete milestones".to_string(),
      description: "Delete milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "milestones.update".to_string(),
      display_name: "Update milestones".to_string(),
      description: "Update milestones on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "projects.get".to_string(),
      display_name: "Get projects".to_string(),
      description: "Get a specific project on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "projects.list".to_string(),
      display_name: "List projects".to_string(),
      description: "List all projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "projects.create".to_string(),
      display_name: "Create projects".to_string(),
      description: "Create new projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "projects.update".to_string(),
      display_name: "Update projects".to_string(),
      description: "Update projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "projects.delete".to_string(),
      display_name: "Delete projects".to_string(),
      description: "Delete projects on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "roles.get".to_string(),
      display_name: "Get roles".to_string(),
      description: "Get roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "roles.list".to_string(),
      display_name: "List roles".to_string(),
      description: "List roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "roles.create".to_string(),
      display_name: "Create roles".to_string(),
      description: "Create roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "roles.update".to_string(),
      display_name: "Update roles".to_string(),
      description: "Update roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "roles.delete".to_string(),
      display_name: "Delete roles".to_string(),
      description: "Delete roles on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "serverLogEntries.get".to_string(),
      display_name: "Get server log entries".to_string(),
      description: "Get a specific server log entry on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "serverLogEntries.list".to_string(),
      display_name: "List server log entries".to_string(),
      description: "List all server log entries on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "serverLogEntries.delete".to_string(),
      display_name: "Delete server log entries".to_string(),
      description: "Delete server log entries on a particular scope. This can be a dangerous action to grant permissions for, as it can affect auditing.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "sessions.get".to_string(),
      display_name: "Get sessions".to_string(),
      description: "Get a specific session on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "sessions.list".to_string(),
      display_name: "List sessions".to_string(),
      description: "List all sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "sessions.create".to_string(),
      display_name: "Create sessions".to_string(),
      description: "Create sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "sessions.delete".to_string(),
      display_name: "Delete sessions".to_string(),
      description: "Delete sessions on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "users.get".to_string(),
      display_name: "Get users".to_string(),
      description: "Get a specific user on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "users.list".to_string(),
      display_name: "List users".to_string(),
      description: "List all users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "users.create".to_string(),
      display_name: "Create users".to_string(),
      description: "Create users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "users.update".to_string(),
      display_name: "Update users".to_string(),
      description: "Update users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "users.delete".to_string(),
      display_name: "Delete users".to_string(),
      description: "Delete users on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "views.get".to_string(),
      display_name: "Get views".to_string(),
      description: "Get a specific view on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "views.list".to_string(),
      display_name: "List views".to_string(),
      description: "List all views on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "views.create".to_string(),
      display_name: "Create views".to_string(),
      description: "Create new views on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "views.update".to_string(),
      display_name: "Update views".to_string(),
      description: "Update views on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "views.delete".to_string(),
      display_name: "Delete views".to_string(),
      description: "Delete views on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "workspaces.get".to_string(),
      display_name: "Get workspaces".to_string(),
      description: "Get a specific workspace on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "workspaces.list".to_string(),
      display_name: "List workspaces".to_string(),
      description: "List all workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "workspaces.create".to_string(),
      display_name: "Create workspaces".to_string(),
      description: "Create new workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "workspaces.update".to_string(),
      display_name: "Update workspaces".to_string(),
      description: "Update workspaces on a particular scope.".to_string(),
      ..Default::default()
    },
    InitialActionProperties {
      name: "workspaces.delete".to_string(),
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

pub async fn initialize_predefined_configurations(database_pool: &deadpool_postgres::Pool) -> Result<Vec<Configuration>, ResourceError> {

  println!("{}", "Initializing predefined configurations...".dimmed());

  let predefined_configurations: Vec<InitialConfigurationProperties> = vec![
    InitialConfigurationProperties {
      name: "actions.allowedNameRegex".to_string(),
      description: Some("A regular expression that action names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
      value_type: ConfigurationValueType::Text,
      default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "actions.allowedDisplayNameRegex".to_string(),
      description: Some("A regular expression that action display names must match in order to be allowed.".to_string()),
      value_type: ConfigurationValueType::Text,
      default_text_value: Some("^.+$".to_string()),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "actions.maximumNameLength".to_string(),
      description: Some("The maximum length of action names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(128 as i64)),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "actions.maximumDisplayNameLength".to_string(),
      description: Some("The maximum length of action display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(128 as i64)),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "actionLogEntries.shouldExpire".to_string(),
      description: Some("Whether action log entries should expire after a certain amount of time. If true, action log entries will expire after the amount of time specified in the \"actionLogEntries.defaultMaximumLifetimeMilliseconds\" configuration.".to_string()),
      value_type: ConfigurationValueType::Boolean,
      default_boolean_value: Some(false),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "actionLogEntries.defaultMaximumLifetimeMilliseconds".to_string(),
      description: Some("The default maximum lifetime of action log entries in milliseconds. This configuration only has an effect if the \"actionLogEntries.shouldExpire\" configuration is set to true.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(31536000000 as i64)), // 365 days in milliseconds
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "apps.allowedNameRegex".to_string(),
      description: Some("A regular expression that app names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
      value_type: ConfigurationValueType::Text,
      default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "apps.maximumNameLength".to_string(),
      description: Some("The maximum length of app names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(32 as i64)),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "apps.allowedDisplayNameRegex".to_string(),
      description: Some("A regular expression that app display names must match in order to be allowed.".to_string()),
      value_type: ConfigurationValueType::Text,
      default_text_value: Some("^.+$".to_string()),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "apps.maximumDisplayNameLength".to_string(),
      description: Some("The maximum length of app display names. Slashstep Group recommends setting this to a reasonable value to prevent abuse.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(64 as i64)),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "appAuthorizationCredentials.accessTokenMaximumLifetimeMilliseconds".to_string(),
      description: Some("The maximum lifetime of app authorization credentials access tokens in milliseconds. Slashstep Group recommends keeping this value small, as OAuth access tokens should be short-lived.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(28800000 as i64)), // 8 hours in milliseconds
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "appAuthorizationCredentials.refreshTokenMaximumLifetimeMilliseconds".to_string(),
      description: Some("The maximum lifetime of app authorization credentials refresh tokens in milliseconds. Slashstep Group recommends setting this to a reasonable value to prevent abuse.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(2592000000 as i64)), // 30 days in milliseconds
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "fields.allowedNameRegex".to_string(),
      description: Some("A regular expression that field names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
      value_type: ConfigurationValueType::Text,
      default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "fields.maximumNameLength".to_string(),
      description: Some("The maximum length of field names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(256 as i64)),
      ..Default::default()
    },
    InitialConfigurationProperties {
      name: "fields.maximumDisplayNameLength".to_string(),
      description: Some("The maximum length of field display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
      value_type: ConfigurationValueType::Number,
      default_number_value: Some(Decimal::from(256 as i64)),
      ..Default::default()
    }
  ];

  let mut configurations: Vec<Configuration> = Vec::new();

  for predefined_configuration in predefined_configurations {

    // Make sure we didn't go through this configuration already.
    let mut should_continue = false;
    for configuration in configurations.iter() {

      if configuration.name == predefined_configuration.name {

        println!("{}", format!("Skipping predefined configuration \"{}\" because it already exists.", predefined_configuration.name).yellow());
        should_continue = true;

      }

    }

    if should_continue {

      continue;

    }

    // Create the configuration, but if it already exists, add it to the list of configurations.
    let configuration = match Configuration::create(&predefined_configuration, database_pool).await {

      Ok(configuration) => configuration,

      Err(error) => match error {

        ResourceError::ConflictError(_) => Configuration::get_by_name(&predefined_configuration.name, database_pool).await?,

        _ => return Err(error)

      }

    };
    configurations.push(configuration);

  }

  println!("{}", format!("Successfully initialized {} predefined configurations.", configurations.len()).blue());

  return Ok(configurations);

}