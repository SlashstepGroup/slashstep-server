use std::collections::HashMap;

use crate::resources::{
    ResourceError, ResourceType,
    access_policy::{
        AccessPolicy, AccessPolicyPrincipalType, InitialAccessPolicyProperties, PermissionLevel,
    },
    action::{Action, InitialActionProperties},
    configuration::{Configuration, ConfigurationValueType, InitialConfigurationProperties},
    group::{Group, GroupParentResourceType, InitialGroupProperties, PredefinedGroupType},
    role::{InitialRoleProperties, PredefinedRoleType, Role, RoleParentResourceType},
};
use colored::Colorize;
use rust_decimal::Decimal;
use tracing::{debug, trace, warn};

pub async fn initialize_predefined_actions(
    database_pool: &deadpool_postgres::Pool,
) -> Result<(), ResourceError> {
    trace!("Initializing predefined actions...");

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
        name: "actions.create".to_string(),
        display_name: "Create actions".to_string(),
        description: "Create new actions on a particular scope.".to_string(),
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
        name: "groups.join".to_string(),
        display_name: "Join groups".to_string(),
        description: "Join a specific group on a particular scope.".to_string(),
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
        name: "itemTypes.get".to_string(),
        display_name: "Get item types".to_string(),
        description: "Get a specific item type on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypes.list".to_string(),
        display_name: "List item types".to_string(),
        description: "List all item types on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypes.create".to_string(),
        display_name: "Create item types".to_string(),
        description: "Create new item types on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypes.update".to_string(),
        display_name: "Update item types".to_string(),
        description: "Update item types on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypes.delete".to_string(),
        display_name: "Delete item types".to_string(),
        description: "Delete item types on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypeIcons.get".to_string(),
        display_name: "Get item type icons".to_string(),
        description: "Get a specific item type icon on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypeIcons.list".to_string(),
        display_name: "List item type icons".to_string(),
        description: "List all item type icons on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypeIcons.create".to_string(),
        display_name: "Create item type icons".to_string(),
        description: "Create new item type icons on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypeIcons.update".to_string(),
        display_name: "Update item type icons".to_string(),
        description: "Update item type icons on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "itemTypeIcons.delete".to_string(),
        display_name: "Delete item type icons".to_string(),
        description: "Delete item type icons on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "iterations.get".to_string(),
        display_name: "Get iterations".to_string(),
        description: "Get a specific iteration on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "iterations.list".to_string(),
        display_name: "List iterations".to_string(),
        description: "List all iterations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "iterations.create".to_string(),
        display_name: "Create iterations".to_string(),
        description: "Create new iterations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "iterations.update".to_string(),
        display_name: "Update iterations".to_string(),
        description: "Update iterations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "iterations.delete".to_string(),
        display_name: "Delete iterations".to_string(),
        description: "Delete iterations on a particular scope.".to_string(),
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
        name: "memberships.renounce".to_string(),
        display_name: "Renounce memberships".to_string(),
        description: "Renounce memberships on a particular scope. This action that allows principals to remove themselves from groups or roles.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.accept".to_string(),
        display_name: "Accept membership invitations".to_string(),
        description: "Accept membership invitations on a particular scope. This action allows principals to accept invitations to join groups or roles.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.get".to_string(),
        display_name: "Get membership invitations".to_string(),
        description: "Get a specific membership invitation on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.list".to_string(),
        display_name: "List membership invitations".to_string(),
        description: "List all membership invitations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.create".to_string(),
        display_name: "Create membership invitations".to_string(),
        description: "Create new membership invitations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.delete".to_string(),
        display_name: "Delete membership invitations".to_string(),
        description: "Delete membership invitations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "membershipInvitations.accept".to_string(),
        display_name: "Accept membership invitations".to_string(),
        description: "Accept membership invitations on a particular scope. This action allows principals to accept invitations to join groups or roles.".to_string(),
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
        name: "oauthAuthorizations.create".to_string(),
        display_name: "Create OAuth authorizations".to_string(),
        description: "Create OAuth authorizations on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "passwordResetAuthorizations.get".to_string(),
        display_name: "Get password reset authorizations".to_string(),
        description: "Get a specific password reset authorization on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "passwordResetAuthorizations.list".to_string(),
        display_name: "List password reset authorizations".to_string(),
        description: "List all password reset authorizations on a particular scope.".to_string(),
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
        name: "roles.join".to_string(),
        display_name: "Join roles".to_string(),
        description: "Join a specific role on a particular scope.".to_string(),
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
        name: "sessionCredentials.create".to_string(),
        display_name: "Create session credentials".to_string(),
        description: "Create session credentials on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "sessionCredentials.get".to_string(),
        display_name: "Get session credentials".to_string(),
        description: "Get a specific session credential on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "sessionCredentials.list".to_string(),
        display_name: "List session credentials".to_string(),
        description: "List all session credentials on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "sessionCredentials.delete".to_string(),
        display_name: "Delete session credentials".to_string(),
        description: "Delete session credentials on a particular scope.".to_string(),
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
        name: "sessions.delete".to_string(),
        display_name: "Delete sessions".to_string(),
        description: "Delete sessions on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "statuses.get".to_string(),
        display_name: "Get statuses".to_string(),
        description: "Get a specific status on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "statuses.list".to_string(),
        display_name: "List statuses".to_string(),
        description: "List all statuses on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "statuses.create".to_string(),
        display_name: "Create statuses".to_string(),
        description: "Create new statuses on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "statuses.update".to_string(),
        display_name: "Update statuses".to_string(),
        description: "Update statuses on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "statuses.delete".to_string(),
        display_name: "Delete statuses".to_string(),
        description: "Delete statuses on a particular scope.".to_string(),
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
        name: "viewFields.get".to_string(),
        display_name: "Get view fields".to_string(),
        description: "Get a specific view field on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "viewFields.list".to_string(),
        display_name: "List view fields".to_string(),
        description: "List all view fields on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "viewFields.create".to_string(),
        display_name: "Create view fields".to_string(),
        description: "Create new view fields on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "viewFields.update".to_string(),
        display_name: "Update view fields".to_string(),
        description: "Update view fields on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "viewFields.delete".to_string(),
        display_name: "Delete view fields".to_string(),
        description: "Delete view fields on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "webhooks.get".to_string(),
        display_name: "Get webhooks".to_string(),
        description: "Get a specific webhook on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "webhooks.list".to_string(),
        display_name: "List webhooks".to_string(),
        description: "List all webhooks on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "webhooks.create".to_string(),
        display_name: "Create webhooks".to_string(),
        description: "Create new webhooks on a particular scope.".to_string(),
        ..Default::default()
    },
    InitialActionProperties {
        name: "webhooks.delete".to_string(),
        display_name: "Delete webhooks".to_string(),
        description: "Delete webhooks on a particular scope.".to_string(),
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
    let mut skipped_action_count = 0;

    for predefined_action in predefined_actions {
        // Make sure we didn't go through this action already.
        let mut should_continue = false;
        for action in actions.iter() {
            if action.name == predefined_action.name {
                warn!(
                    "Skipping predefined action \"{}\" because it already exists.",
                    predefined_action.name
                );
                should_continue = true;
            }
        }

        if should_continue {
            continue;
        }

        // Create the action, but if it already exists, add it to the list of actions.
        let action = match Action::create(&predefined_action, database_pool).await {
            Ok(action) => action,

            Err(error) => match error {
                ResourceError::ConflictError(_) => {
                    skipped_action_count += 1;
                    continue;
                }

                _ => return Err(error),
            },
        };
        actions.push(action);
    }

    debug!("Successfully initialized {} predefined actions. {} actions were skipped because they already existed.", actions.len(), skipped_action_count);

    Ok(())
}

pub async fn initialize_predefined_groups(
    database_pool: &deadpool_postgres::Pool,
) -> Result<(), ResourceError> {
    debug!("Initializing predefined groups...");

    let predefined_groups: Vec<InitialGroupProperties> = vec![
    InitialGroupProperties {
        name: "anonymous-users".to_string(),
        display_name: "Anonymous users".to_string(),
        description: Some("Users who have not logged in. Registered users should not be assigned this group.".to_string()),
        parent_resource_type: GroupParentResourceType::Server,
        predefined_group_type: Some(PredefinedGroupType::AnonymousUsers),
        ..Default::default()
    },
    InitialGroupProperties {
        name: "registered-users".to_string(),
        display_name: "Registered users".to_string(),
        description: Some("Users who have a registered identity. Anonymous users should not be assigned this group.".to_string()),
        parent_resource_type: GroupParentResourceType::Server,
        predefined_group_type: Some(PredefinedGroupType::RegisteredUsers),
        ..Default::default()
    },
  ];

    let action_mappings = HashMap::from([
        (
            PredefinedGroupType::AnonymousUsers,
            vec![
                ("users.create", PermissionLevel::User),
                ("sessionCredentials.create", PermissionLevel::User),
            ],
        ),
        (
            PredefinedGroupType::RegisteredUsers,
            vec![
                ("configurations.list", PermissionLevel::User),
                ("items.list", PermissionLevel::User),
                ("projects.list", PermissionLevel::User),
                ("groups.create", PermissionLevel::User),
                ("groups.list", PermissionLevel::User),
                ("memberships.list", PermissionLevel::User),
                ("membershipInvitations.list", PermissionLevel::User),
                ("milestones.list", PermissionLevel::User),
                ("users.list", PermissionLevel::User),
                ("workspaces.create", PermissionLevel::User),
                ("workspaces.list", PermissionLevel::User),
                ("sessionCredentials.create", PermissionLevel::User),
            ],
        ),
    ]);

    let mut groups: Vec<Group> = Vec::new();
    let mut skipped_group_count = 0;

    for initial_predefined_group_properties in predefined_groups {
        // Make sure we didn't go through this group already.
        let mut should_continue = false;
        for group in groups.iter() {
            if group.name == initial_predefined_group_properties.name {
                warn!(
                    "Skipping predefined group \"{}\" because it already exists.",
                    initial_predefined_group_properties.name
                );
                should_continue = true;
            }
        }

        if should_continue {
            continue;
        }

        // Create the group, but if it already exists, add it to the list of groups.
        let predefined_group =
            match Group::create(&initial_predefined_group_properties, database_pool).await {
                Ok(group) => group,

                Err(error) => match error {
                    ResourceError::ConflictError(_) => {
                        skipped_group_count += 1;
                        continue;
                    }

                    _ => return Err(error),
                },
            };
        groups.push(predefined_group.clone());

        if let Some(predefined_group_type) = predefined_group.predefined_group_type
            && let Some(action_mappings_for_group) = action_mappings.get(&predefined_group_type)
        {
            for (action_name, permission_level) in action_mappings_for_group.iter() {
                let action = match Action::get_by_name(action_name, database_pool).await {
                    Ok(action) => action,

                    Err(error) => return Err(error),
                };

                AccessPolicy::create(
                    &InitialAccessPolicyProperties {
                        action_id: action.id,
                        permission_level: *permission_level,
                        is_inheritance_enabled: true,
                        principal_type: AccessPolicyPrincipalType::Group,
                        principal_user_id: None,
                        principal_role_id: None,
                        principal_app_id: None,
                        principal_group_id: Some(predefined_group.id),
                        scoped_resource_type: ResourceType::Server,
                        ..Default::default()
                    },
                    database_pool,
                )
                .await?;
            }
        }
    }

    debug!("Successfully initialized {} predefined groups. {} groups were skipped because they already existed.", groups.len(), skipped_group_count);

    Ok(())
}

pub async fn initialize_predefined_roles(
    database_pool: &deadpool_postgres::Pool,
) -> Result<(), ResourceError> {
    trace!("Initializing predefined roles...");

    let predefined_roles: Vec<InitialRoleProperties> = vec![
    InitialRoleProperties {
        name: "server-admins".to_string(),
        display_name: "Server admins".to_string(),
        description: Some("Users who have full access to all resources on the server. This role should be assigned to trusted users only.".to_string()),
        parent_resource_type: RoleParentResourceType::Server,
        predefined_role_type: Some(PredefinedRoleType::ServerAdmins),
        ..Default::default()
    }
  ];

    let action_mappings = HashMap::from([(
        PredefinedRoleType::ServerAdmins,
        vec![
            ("accessPolicies.get", PermissionLevel::Admin),
            ("accessPolicies.list", PermissionLevel::Admin),
            ("accessPolicies.create", PermissionLevel::Admin),
            ("accessPolicies.update", PermissionLevel::Admin),
            ("accessPolicies.delete", PermissionLevel::Admin),
            ("actions.get", PermissionLevel::Admin),
            ("actions.list", PermissionLevel::Admin),
            ("actions.create", PermissionLevel::Admin),
            ("actions.update", PermissionLevel::Admin),
            ("actions.delete", PermissionLevel::Admin),
            ("actionLogEntries.get", PermissionLevel::Admin),
            ("actionLogEntries.list", PermissionLevel::Admin),
            ("actionLogEntries.delete", PermissionLevel::Admin),
            ("apps.get", PermissionLevel::Admin),
            ("apps.list", PermissionLevel::Admin),
            ("apps.create", PermissionLevel::Admin),
            ("apps.update", PermissionLevel::Admin),
            ("apps.delete", PermissionLevel::Admin),
            ("apps.authorize", PermissionLevel::Admin),
            ("appCredentials.create", PermissionLevel::Admin),
            ("appCredentials.get", PermissionLevel::Admin),
            ("appCredentials.list", PermissionLevel::Admin),
            ("appCredentials.delete", PermissionLevel::Admin),
            ("appAuthorizations.get", PermissionLevel::Admin),
            ("appAuthorizations.list", PermissionLevel::Admin),
            ("appAuthorizations.create", PermissionLevel::Admin),
            ("appAuthorizations.delete", PermissionLevel::Admin),
            ("appAuthorizationCredentials.get", PermissionLevel::Admin),
            ("appAuthorizationCredentials.list", PermissionLevel::Admin),
            ("appAuthorizationCredentials.create", PermissionLevel::Admin),
            ("appAuthorizationCredentials.delete", PermissionLevel::Admin),
            ("configurations.get", PermissionLevel::Admin),
            ("configurations.list", PermissionLevel::Admin),
            ("configurations.create", PermissionLevel::Admin),
            ("configurations.update", PermissionLevel::Admin),
            ("configurations.delete", PermissionLevel::Admin),
            ("configurationValues.get", PermissionLevel::Admin),
            ("configurationValues.list", PermissionLevel::Admin),
            ("configurationValues.create", PermissionLevel::Admin),
            ("configurationValues.update", PermissionLevel::Admin),
            ("configurationValues.delete", PermissionLevel::Admin),
            ("delegationPolicies.get", PermissionLevel::Admin),
            ("delegationPolicies.list", PermissionLevel::Admin),
            ("delegationPolicies.create", PermissionLevel::Admin),
            ("delegationPolicies.update", PermissionLevel::Admin),
            ("delegationPolicies.delete", PermissionLevel::Admin),
            ("fields.get", PermissionLevel::Admin),
            ("fields.list", PermissionLevel::Admin),
            ("fields.create", PermissionLevel::Admin),
            ("fields.update", PermissionLevel::Admin),
            ("fields.delete", PermissionLevel::Admin),
            ("fieldChoices.get", PermissionLevel::Admin),
            ("fieldChoices.list", PermissionLevel::Admin),
            ("fieldChoices.create", PermissionLevel::Admin),
            ("fieldChoices.update", PermissionLevel::Admin),
            ("fieldChoices.delete", PermissionLevel::Admin),
            ("fieldValues.get", PermissionLevel::Admin),
            ("fieldValues.list", PermissionLevel::Admin),
            ("fieldValues.create", PermissionLevel::Admin),
            ("fieldValues.update", PermissionLevel::Admin),
            ("fieldValues.delete", PermissionLevel::Admin),
            ("groups.get", PermissionLevel::Admin),
            ("groups.list", PermissionLevel::Admin),
            ("groups.create", PermissionLevel::Admin),
            ("groups.join", PermissionLevel::Admin),
            ("groups.update", PermissionLevel::Admin),
            ("groups.delete", PermissionLevel::Admin),
            ("httpTransactions.get", PermissionLevel::Admin),
            ("httpTransactions.list", PermissionLevel::Admin),
            ("httpTransactions.delete", PermissionLevel::Admin),
            ("items.get", PermissionLevel::Admin),
            ("items.list", PermissionLevel::Admin),
            ("items.create", PermissionLevel::Admin),
            ("items.update", PermissionLevel::Admin),
            ("items.delete", PermissionLevel::Admin),
            ("itemConnections.get", PermissionLevel::Admin),
            ("itemConnections.list", PermissionLevel::Admin),
            ("itemConnections.create", PermissionLevel::Admin),
            ("itemConnections.update", PermissionLevel::Admin),
            ("itemConnections.delete", PermissionLevel::Admin),
            ("itemConnectionTypes.get", PermissionLevel::Admin),
            ("itemConnectionTypes.list", PermissionLevel::Admin),
            ("itemConnectionTypes.create", PermissionLevel::Admin),
            ("itemConnectionTypes.update", PermissionLevel::Admin),
            ("itemConnectionTypes.delete", PermissionLevel::Admin),
            ("itemTypes.get", PermissionLevel::Admin),
            ("itemTypes.list", PermissionLevel::Admin),
            ("itemTypes.create", PermissionLevel::Admin),
            ("itemTypes.update", PermissionLevel::Admin),
            ("itemTypes.delete", PermissionLevel::Admin),
            ("itemTypeIcons.get", PermissionLevel::Admin),
            ("itemTypeIcons.list", PermissionLevel::Admin),
            ("itemTypeIcons.create", PermissionLevel::Admin),
            ("itemTypeIcons.update", PermissionLevel::Admin),
            ("itemTypeIcons.delete", PermissionLevel::Admin),
            ("iterations.get", PermissionLevel::Admin),
            ("iterations.list", PermissionLevel::Admin),
            ("iterations.create", PermissionLevel::Admin),
            ("iterations.update", PermissionLevel::Admin),
            ("iterations.delete", PermissionLevel::Admin),
            ("memberships.get", PermissionLevel::Admin),
            ("memberships.list", PermissionLevel::Admin),
            ("memberships.create", PermissionLevel::Admin),
            ("memberships.delete", PermissionLevel::Admin),
            ("memberships.renounce", PermissionLevel::Admin),
            ("membershipInvitations.accept", PermissionLevel::Admin),
            ("membershipInvitations.get", PermissionLevel::Admin),
            ("membershipInvitations.list", PermissionLevel::Admin),
            ("membershipInvitations.create", PermissionLevel::Admin),
            ("membershipInvitations.delete", PermissionLevel::Admin),
            ("milestones.get", PermissionLevel::Admin),
            ("milestones.list", PermissionLevel::Admin),
            ("milestones.create", PermissionLevel::Admin),
            ("milestones.update", PermissionLevel::Admin),
            ("milestones.delete", PermissionLevel::Admin),
            ("oauthAuthorizations.create", PermissionLevel::Admin),
            ("projects.get", PermissionLevel::Admin),
            ("projects.list", PermissionLevel::Admin),
            ("projects.create", PermissionLevel::Admin),
            ("projects.update", PermissionLevel::Admin),
            ("projects.delete", PermissionLevel::Admin),
            ("roles.get", PermissionLevel::Admin),
            ("roles.list", PermissionLevel::Admin),
            ("roles.create", PermissionLevel::Admin),
            ("roles.update", PermissionLevel::Admin),
            ("roles.delete", PermissionLevel::Admin),
            ("serverLogEntries.get", PermissionLevel::Admin),
            ("serverLogEntries.list", PermissionLevel::Admin),
            ("serverLogEntries.delete", PermissionLevel::Admin),
            ("sessionCredentials.create", PermissionLevel::Admin),
            ("sessionCredentials.get", PermissionLevel::Admin),
            ("sessionCredentials.list", PermissionLevel::Admin),
            ("sessionCredentials.delete", PermissionLevel::Admin),
            ("sessions.get", PermissionLevel::Admin),
            ("sessions.list", PermissionLevel::Admin),
            ("sessions.delete", PermissionLevel::Admin),
            ("statuses.get", PermissionLevel::Admin),
            ("statuses.list", PermissionLevel::Admin),
            ("statuses.create", PermissionLevel::Admin),
            ("statuses.update", PermissionLevel::Admin),
            ("statuses.delete", PermissionLevel::Admin),
            ("users.get", PermissionLevel::Admin),
            ("users.list", PermissionLevel::Admin),
            ("users.create", PermissionLevel::Admin),
            ("users.update", PermissionLevel::Admin),
            ("users.delete", PermissionLevel::Admin),
            ("views.get", PermissionLevel::Admin),
            ("views.list", PermissionLevel::Admin),
            ("views.create", PermissionLevel::Admin),
            ("views.update", PermissionLevel::Admin),
            ("views.delete", PermissionLevel::Admin),
            ("viewFields.get", PermissionLevel::Admin),
            ("viewFields.list", PermissionLevel::Admin),
            ("viewFields.create", PermissionLevel::Admin),
            ("viewFields.update", PermissionLevel::Admin),
            ("viewFields.delete", PermissionLevel::Admin),
            ("webhooks.get", PermissionLevel::Admin),
            ("webhooks.list", PermissionLevel::Admin),
            ("webhooks.create", PermissionLevel::Admin),
            ("webhooks.delete", PermissionLevel::Admin),
            ("workspaces.get", PermissionLevel::Admin),
            ("workspaces.list", PermissionLevel::Admin),
            ("workspaces.create", PermissionLevel::Admin),
            ("workspaces.update", PermissionLevel::Admin),
            ("workspaces.delete", PermissionLevel::Admin),
        ],
    )]);

    let mut roles: Vec<Role> = Vec::new();
    let mut skipped_role_count = 0;

    for initial_predefined_role_propertiess in predefined_roles {
        // Make sure we didn't go through this role already.
        let mut should_continue = false;
        for role in roles.iter() {
            if role.name == initial_predefined_role_propertiess.name {
                warn!(
                    "Skipping predefined role \"{}\" because that was already checked.",
                    initial_predefined_role_propertiess.name
                );
                should_continue = true;
            }
        }

        if should_continue {
            continue;
        }

        // Create the role, but if it already exists, add it to the list of roles.
        let predefined_role =
            match Role::create(&initial_predefined_role_propertiess, database_pool).await {
                Ok(role) => role,

                Err(error) => match error {
                    ResourceError::ConflictError(_) => {
                        skipped_role_count += 1;
                        continue;
                    }

                    _ => return Err(error),
                },
            };
        roles.push(predefined_role.clone());

        if let Some(predefined_role_type) = predefined_role.predefined_role_type
            && let Some(action_mappings_for_role) = action_mappings.get(&predefined_role_type)
        {
            for (action_name, permission_level) in action_mappings_for_role.iter() {
                let action = match Action::get_by_name(action_name, database_pool).await {
                    Ok(action) => action,

                    Err(error) => return Err(error),
                };

                AccessPolicy::create(
                    &InitialAccessPolicyProperties {
                        action_id: action.id,
                        permission_level: *permission_level,
                        is_inheritance_enabled: true,
                        principal_type: AccessPolicyPrincipalType::Role,
                        principal_user_id: None,
                        principal_role_id: Some(predefined_role.id),
                        principal_app_id: None,
                        principal_group_id: None,
                        scoped_resource_type: ResourceType::Server,
                        ..Default::default()
                    },
                    database_pool,
                )
                .await?;
            }
        }
    }

    debug!("Successfully initialized {} predefined roles. {} roles were skipped because they already existed.", roles.len(), skipped_role_count);

    Ok(())
}

pub async fn initialize_predefined_configurations(
    database_pool: &deadpool_postgres::Pool,
) -> Result<(), ResourceError> {
    debug!("Initializing predefined configurations...");

    let predefined_configurations: Vec<InitialConfigurationProperties> = vec![
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerAppPerMinute".to_string(),
        description: Some("The maximum number of total read requests per minute per app. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once an app exceeds this limit, it will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(10))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerAnonymousUserPerMinute".to_string(),
        description: Some("The maximum number of total read requests per minute per anonymous user. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(7))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerRegisteredUserPerMinute".to_string(),
        description: Some("The maximum number of total read requests per minute per registered user. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(7))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerAppPerSecond".to_string(),
        description: Some("The maximum number of total read requests per second per app. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once an app exceeds this limit, it will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerAnonymousUserPerSecond".to_string(),
        description: Some("The maximum number of total read requests per second per anonymous user. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(4))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumReadRequestCountPerRegisteredUserPerSecond".to_string(),
        description: Some("The maximum number of total read requests per second per registered user. Unless described otherwise, any request to an endpoint with a method of GET will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(5))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumWriteRequestCountPerAppPerMinute".to_string(),
        description: Some("The maximum number of total write requests per minute per app. Unless described otherwise, any request to an endpoint with a method of DELETE, PATCH, POST, or PUT will be subject to this rate limit. Once an app exceeds this limit, it will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(10))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumWriteRequestCountPerAnonymousUserPerMinute".to_string(),
        description: Some("The maximum number of total write requests per minute per anonymous user. Unless described otherwise, any request to an endpoint with a method of DELETE, PATCH, POST, or PUT will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(3))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumWriteRequestCountPerRegisteredUserPerMinute".to_string(),
        description: Some("The maximum number of total write requests per minute per registered user. Unless described otherwise, any request to an endpoint with a method of DELETE, PATCH, POST, or PUT will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumWriteRequestCountPerAnonymousUserPerSecond".to_string(),
        description: Some("The maximum number of total write requests per second per anonymous user. Unless described otherwise, any request to an endpoint with a method of DELETE, PATCH, POST, or PUT will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(1))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "server.absoluteMaximumWriteRequestCountPerRegisteredUserPerSecond".to_string(),
        description: Some("The maximum number of total write requests per second per registered user. Unless described otherwise, any request to an endpoint with a method of DELETE, PATCH, POST, or PUT will be subject to this rate limit. This rate limit also applies for apps when they act on behalf of users. Once a user exceeds this limit, they will be rate-limited.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(5))),
        ..Default::default()
    },
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
        default_number_value: Some(Decimal::from(2_i64.pow(7))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "actions.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of action display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(7))),
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
        default_number_value: Some(Decimal::from(31536000000_i64)), // 365 days in milliseconds
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
        default_number_value: Some(Decimal::from(2_i64.pow(5))),
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
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "appAuthorizationCredentials.accessTokenMaximumLifetimeMilliseconds".to_string(),
        description: Some("The maximum lifetime of app authorization credentials access tokens in milliseconds. Slashstep Group recommends keeping this value small, as OAuth access tokens should be short-lived.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(28800000_i64)), // 8 hours in milliseconds
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "appAuthorizationCredentials.refreshTokenMaximumLifetimeMilliseconds".to_string(),
        description: Some("The maximum lifetime of app authorization credentials refresh tokens in milliseconds. Slashstep Group recommends setting this to a reasonable value to prevent abuse.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2594000000_i64)), // 30 days in milliseconds
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
        name: "fields.allowedDisplayNameRegex".to_string(),
        description: Some("A regular expression that field display names must match in order to be allowed.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^.+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fields.maximumNameLength".to_string(),
        description: Some("The maximum length of field names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fields.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of field descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(10))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fields.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of field display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fieldValues.maximumTextValueLength".to_string(),
        description: Some("The maximum length of field value text values in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(15))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fieldValues.maximumNumberValue".to_string(),
        description: Some("The maximum number value that is allowed for field values. Slashstep Group recommends keeping this value at a reasonable number to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(i64::MAX)),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "fieldValues.minimumNumberValue".to_string(),
        description: Some("The minimum number value that is allowed for field values. Slashstep Group recommends keeping this value at a reasonable number to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(i64::MIN)),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "groups.allowedNameRegex".to_string(),
        description: Some("A regular expression that group names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "groups.maximumNameLength".to_string(),
        description: Some("The maximum length of group names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(5))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "groups.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of group display names. Slashstep Group recommends setting this to a reasonable value to prevent abuse.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "groups.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of group descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(10))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "httpTransactions.shouldExpire".to_string(),
        description: Some("Whether HTTP transactions should expire after a certain amount of time. If true, HTTP transactions will expire after the amount of time specified in the \"httpTransactions.defaultMaximumLifetimeMilliseconds\" configuration.".to_string()),
        value_type: ConfigurationValueType::Boolean,
        default_boolean_value: Some(true),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "httpTransactions.defaultMaximumLifetimeMilliseconds".to_string(),
        description: Some("The default maximum lifetime of HTTP transactions in milliseconds. This configuration only has an effect if the \"httpTransactions.shouldExpire\" configuration is set to true.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(31536000000_i64)), // 365 days in milliseconds
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "users.shouldSetupAdminUser".to_string(),
        description: Some("Whether the first admin user should be set up automatically. If true, the console will prompt the user to set up an admin user prior to starting the server.".to_string()),
        value_type: ConfigurationValueType::Boolean,
        default_boolean_value: Some(true),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "items.maximumSummaryLength".to_string(),
        description: Some("The maximum length of item summaries in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemConnectionTypes.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of item connection type display names. Slashstep Group recommends setting this to a reasonable value to prevent abuse.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemConnectionTypes.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of item connection type descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypes.maximumNameLength".to_string(),
        description: Some("The maximum length of item type names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypes.allowedNameRegex".to_string(),
        description: Some("A regular expression that item type names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypes.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of item type display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypes.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of item type descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypeIcons.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of item type icon display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "itemTypeIcons.storageDirectoryPath".to_string(),
        description: Some("The file system directory path where item type icons are stored. If the directory doesn't exist, it will be created when it's needed.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("./media/item-type-icons".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "iterations.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of iteration display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "milestones.allowedNameRegex".to_string(),
        description: Some("A regular expression that milestone names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "milestones.maximumNameLength".to_string(),
        description: Some("The maximum length of milestone names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "milestones.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of milestone display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "milestones.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of milestone descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.maximumNameLength".to_string(),
        description: Some("The maximum length of project names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of project display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.maximumKeyLength".to_string(),
        description: Some("The maximum length of project keys in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(4))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of project descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.allowedNameRegex".to_string(),
        description: Some("A regular expression that project names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "projects.allowedKeyRegex".to_string(),
        description: Some("A regular expression that project keys must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "roles.maximumNameLength".to_string(),
        description: Some("The maximum length of role names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "roles.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of role display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "roles.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of role descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "roles.allowedNameRegex".to_string(),
        description: Some("A regular expression that role names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "sessions.maximumLifetimeMilliseconds".to_string(),
        description: Some("The maximum lifetime of sessions in milliseconds. Slashstep Group recommends setting this to a reasonable value to preserve security.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(7_776_000_000_i64)), // 90 days in milliseconds
          ..Default::default()
    },
    InitialConfigurationProperties {
        name: "sessionCredentials.maximumAccessTokenLifetimeMilliseconds".to_string(),
        description: Some("The maximum lifetime of access tokens in milliseconds. Slashstep Group recommends setting this to a reasonable value to preserve security.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(28_800_000_i64)), // 8 hours in milliseconds
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "sessionCredentials.maximumRefreshTokenLifetimeMilliseconds".to_string(),
        description: Some("The maximum lifetime of session refresh tokens in milliseconds. Slashstep Group recommends setting this to a reasonable value to preserve security. If this value is the same value as the access token lifetime or lesser, this configuration will effectively disable refresh tokens for sessions. In this case, users need to reauthenticate after the access token expires.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_592_000_000_i64)), // 30 days in milliseconds
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "statuses.maximumNameLength".to_string(),
        description: Some("The maximum length of status names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "statuses.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of status display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "statuses.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of status descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(8))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "statuses.allowedNameRegex".to_string(),
        description: Some("A regular expression that status names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "users.allowedNameRegex".to_string(),
        description: Some("A regular expression that user names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "users.maximumNameLength".to_string(),
        description: Some("The maximum length of user names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "users.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of user display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "users.maximumPasswordLength".to_string(),
        description: Some("The maximum length of user passwords in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance while still allowing for secure passwords.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(7))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "views.maximumNameLength".to_string(),
        description: Some("The maximum length of view names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "views.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of view display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "views.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of view descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(11))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "views.allowedNameRegex".to_string(),
        description: Some("A regular expression that view names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "workspaces.maximumNameLength".to_string(),
        description: Some("The maximum length of workspace names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "workspaces.maximumDisplayNameLength".to_string(),
        description: Some("The maximum length of workspace display names in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(6))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "workspaces.maximumDescriptionLength".to_string(),
        description: Some("The maximum length of workspace descriptions in characters. Slashstep Group recommends keeping this value at a reasonable length to maintain performance.".to_string()),
        value_type: ConfigurationValueType::Number,
        default_number_value: Some(Decimal::from(2_i64.pow(11))),
        ..Default::default()
    },
    InitialConfigurationProperties {
        name: "workspaces.allowedNameRegex".to_string(),
        description: Some("A regular expression that workspace names must match in order to be allowed. Slashstep Group recommends using a regex pattern that is URL-safe.".to_string()),
        value_type: ConfigurationValueType::Text,
        default_text_value: Some("^[a-zA-Z0-9._-]+$".to_string()),
        ..Default::default()
    }
  ];

    let mut configurations: Vec<Configuration> = Vec::new();
    let mut skipped_configuration_count = 0;

    for predefined_configuration in predefined_configurations {
        // Make sure we didn't go through this configuration already.
        let mut should_continue = false;
        for configuration in configurations.iter() {
            if configuration.name == predefined_configuration.name {
                warn!(
                    "Skipping predefined configuration \"{}\" because it already exists.",
                    predefined_configuration.name
                );
                should_continue = true;
            }
        }

        if should_continue {
            continue;
        }

        // Create the configuration, but if it already exists, add it to the list of configurations.
        let configuration =
            match Configuration::create(&predefined_configuration, database_pool).await {
                Ok(configuration) => configuration,

                Err(error) => match error {
                    ResourceError::ConflictError(_) => {
                        skipped_configuration_count += 1;
                        continue;
                    }

                    _ => return Err(error),
                },
            };
        configurations.push(configuration);
    }

    debug!("Successfully initialized {} predefined configurations. {} configurations were skipped because they already existed.", configurations.len(), skipped_configuration_count);

    Ok(())
}
