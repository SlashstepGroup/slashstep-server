use pg_escape::quote_literal;
use thiserror::Error;
use uuid::Uuid;

use crate::resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyResourceType, ActionPermissionLevel}, action::Action, app::{App, AppParentResourceType}, app_authorization::{AppAuthorization, AppAuthorizationAuthorizingResourceType}, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, field::Field, field_choice::FieldChoice, field_value::{FieldValue, FieldValueParentResourceType}, item::Item, item_connection::ItemConnection, item_connection_type::{ItemConnectionType, ItemConnectionTypeParentResourceType}, membership::{Membership, MembershipParentResourceType}, membership_invitation::MembershipInvitation, milestone::{Milestone, MilestoneParentResourceType}, project::Project, role::{Role, RoleParentResourceType}, session::Session};

pub type ResourceHierarchy = Vec<(AccessPolicyResourceType, Option<Uuid>)>;

#[derive(Debug, Clone)]
pub enum PrincipalWithID {

  User(Uuid),

  Group(Uuid),

  Role(Uuid),

  App(Uuid)

}

#[derive(Debug, Error)]
pub enum ResourceHierarchyError {
  #[error("A scoped resource ID is required for the {0} resource type.")]
  ScopedResourceIDMissingError(AccessPolicyResourceType),

  #[error("An ancestor resource of type {0} is required.")]
  OrphanedResourceError(AccessPolicyResourceType, ResourceHierarchy),

  #[error("{0} resources have multiple owners. Use the get_all_hierarchies() function to get all the resource hierarchies.")]
  MultipleOwnersError(AccessPolicyResourceType),

  #[error("The principal does not have the required permissions to perform the action \"{action_id}\".")]
  ForbiddenError {
    principal: PrincipalWithID,
    action_id: String,
    minimum_permission_level: ActionPermissionLevel,
    actual_permission_level: ActionPermissionLevel
  },

  #[error(transparent)]
  ResourceError(#[from] ResourceError)

}

pub async fn get_hierarchy(scoped_resource_type: &AccessPolicyResourceType, scoped_resource_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<ResourceHierarchy, ResourceHierarchyError> {

  let mut hierarchy: ResourceHierarchy = vec![];
  let mut selected_resource_type: AccessPolicyResourceType = scoped_resource_type.clone();
  let mut selected_resource_id = scoped_resource_id.copied();
  
  loop {

    match selected_resource_type {

      // AccessPolicy -> (AccessPolicy | Action | ActionLogEntry | App | AppAuthorization | AppAuthorizationCredential | AppCredential | Configuration | DelegationPolicy | Field | FieldChoice | FieldValue | Group | HTTPTransaction | Item | ItemConnection | ItemConnectionType | Membership | MembershipInvitation | Milestone | OAuthAuthorization | Project | Role | ServerLogEntry | Session | User | View | Workspace)
      AccessPolicyResourceType::AccessPolicy => {

        let Some(access_policy_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AccessPolicy));

        };

        hierarchy.push((AccessPolicyResourceType::AccessPolicy, Some(access_policy_id)));

        let access_policy = AccessPolicy::get_by_id(&access_policy_id, database_pool).await?;
        selected_resource_type = access_policy.scoped_resource_type;
        selected_resource_id = match access_policy.scoped_resource_type {
        
          AccessPolicyResourceType::AccessPolicy => access_policy.scoped_access_policy_id,
          AccessPolicyResourceType::Action => access_policy.scoped_action_id,
          AccessPolicyResourceType::ActionLogEntry => access_policy.scoped_action_log_entry_id,
          AccessPolicyResourceType::App => access_policy.scoped_app_id,
          AccessPolicyResourceType::AppAuthorization => access_policy.scoped_app_authorization_id,
          AccessPolicyResourceType::AppAuthorizationCredential => access_policy.scoped_app_authorization_credential_id,
          AccessPolicyResourceType::AppCredential => access_policy.scoped_app_credential_id,
          AccessPolicyResourceType::Configuration => access_policy.scoped_configuration_id,
          AccessPolicyResourceType::DelegationPolicy => access_policy.scoped_delegation_policy_id,
          AccessPolicyResourceType::Field => access_policy.scoped_field_id,
          AccessPolicyResourceType::FieldChoice => access_policy.scoped_field_choice_id,
          AccessPolicyResourceType::FieldValue => access_policy.scoped_field_value_id,
          AccessPolicyResourceType::Group => access_policy.scoped_group_id,
          AccessPolicyResourceType::HTTPTransaction => access_policy.scoped_http_transaction_id,
          AccessPolicyResourceType::Item => access_policy.scoped_item_id,
          AccessPolicyResourceType::ItemConnection => access_policy.scoped_item_connection_id,
          AccessPolicyResourceType::ItemConnectionType => access_policy.scoped_item_connection_type_id,
          AccessPolicyResourceType::Membership => access_policy.scoped_membership_id,
          AccessPolicyResourceType::MembershipInvitation => access_policy.scoped_membership_invitation_id,
          AccessPolicyResourceType::Milestone => access_policy.scoped_milestone_id,
          AccessPolicyResourceType::OAuthAuthorization => access_policy.scoped_oauth_authorization_id,
          AccessPolicyResourceType::Project => access_policy.scoped_project_id,
          AccessPolicyResourceType::Role => access_policy.scoped_role_id,
          AccessPolicyResourceType::Server => None,
          AccessPolicyResourceType::ServerLogEntry => access_policy.scoped_server_log_entry_id,
          AccessPolicyResourceType::Session => access_policy.scoped_session_id,
          AccessPolicyResourceType::User => access_policy.scoped_user_id,
          AccessPolicyResourceType::View => access_policy.scoped_view_id,
          AccessPolicyResourceType::Workspace => access_policy.scoped_workspace_id,

        }

      },

      // Action -> (App | Server)
      AccessPolicyResourceType::Action => {

        let Some(action_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Action));

        };

        hierarchy.push((AccessPolicyResourceType::Action, Some(action_id)));

        let action = match Action::get_by_id(&action_id, database_pool).await {

          Ok(action) => action,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Action, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        if let Some(app_id) = action.parent_app_id {

          selected_resource_type = AccessPolicyResourceType::App;
          selected_resource_id = Some(app_id);

        } else {

          selected_resource_type = AccessPolicyResourceType::Server;
          selected_resource_id = None;

        }

      },

      // ActionLogEntry -> Server
      AccessPolicyResourceType::ActionLogEntry => {

        let Some(scoped_action_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ActionLogEntry));

        };

        hierarchy.push((AccessPolicyResourceType::ActionLogEntry, Some(scoped_action_log_entry_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // App -> (Workspace | User | Server)
      AccessPolicyResourceType::App => {

        let Some(app_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::App));

        };

        hierarchy.push((AccessPolicyResourceType::App, Some(app_id)));

        let app = match App::get_by_id(&app_id, database_pool).await {

          Ok(app) => app,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::App, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match app.parent_resource_type {

          AppParentResourceType::Server => {

            selected_resource_type = AccessPolicyResourceType::Server;
            selected_resource_id = None;

          },

          AppParentResourceType::Workspace => {

            let Some(workspace_id) = app.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          AppParentResourceType::User => {

            let Some(user_id) = app.parent_user_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

            };

            selected_resource_type = AccessPolicyResourceType::User;
            selected_resource_id = Some(user_id);

          }

        }

      },

      // AppAuthorization -> (User | Workspace | Server)
      AccessPolicyResourceType::AppAuthorization => {

        let Some(app_authorization_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppAuthorization));

        };

        hierarchy.push((AccessPolicyResourceType::AppAuthorization, Some(app_authorization_id)));

        let app_authorization = match AppAuthorization::get_by_id(&app_authorization_id, database_pool).await {

          Ok(app_authorization) => app_authorization,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorization, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match app_authorization.authorizing_resource_type {

          AppAuthorizationAuthorizingResourceType::Server => {

            selected_resource_type = AccessPolicyResourceType::Server;
            selected_resource_id = None;

          },

          AppAuthorizationAuthorizingResourceType::Project => {

            let Some(project_id) = app_authorization.authorizing_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

            };

            selected_resource_type = AccessPolicyResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          AppAuthorizationAuthorizingResourceType::Workspace => {

            let Some(workspace_id) = app_authorization.authorizing_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          AppAuthorizationAuthorizingResourceType::User => {

            let Some(user_id) = app_authorization.authorizing_user_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

            };

            selected_resource_type = AccessPolicyResourceType::User;
            selected_resource_id = Some(user_id);

          }

        }

      },

      // AppAuthorizationCredential -> AppAuthorization
      AccessPolicyResourceType::AppAuthorizationCredential => {

        let Some(app_authorization_credential_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppAuthorizationCredential));

        };

        hierarchy.push((AccessPolicyResourceType::AppAuthorizationCredential, Some(app_authorization_credential_id)));

        let app_authorization_credential = match AppAuthorizationCredential::get_by_id(&app_authorization_credential_id, database_pool).await {

          Ok(app_authorization_credential) => app_authorization_credential,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorizationCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::AppAuthorization;
        selected_resource_id = Some(app_authorization_credential.app_authorization_id);

      },

      // AppCredential -> App
      AccessPolicyResourceType::AppCredential => {

        let Some(app_credential_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppCredential));

        };

        hierarchy.push((AccessPolicyResourceType::AppCredential, Some(app_credential_id)));

        let app_credential = match AppCredential::get_by_id(&app_credential_id, database_pool).await {

          Ok(app_credential) => app_credential,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::App;
        selected_resource_id = Some(app_credential.app_id);

      },

      // Configuration -> Server
      AccessPolicyResourceType::Configuration => {

        let Some(configuration_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Configuration));

        };

        hierarchy.push((AccessPolicyResourceType::Configuration, Some(configuration_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // DelegationPolicy -> User
      AccessPolicyResourceType::DelegationPolicy => {

        let Some(delegation_policy_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::DelegationPolicy));

        };

        hierarchy.push((AccessPolicyResourceType::DelegationPolicy, Some(delegation_policy_id)));

        let delegation_policy = match crate::resources::delegation_policy::DelegationPolicy::get_by_id(&delegation_policy_id, database_pool).await {

          Ok(delegation_policy) => delegation_policy,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::DelegationPolicy, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::User;
        selected_resource_id = Some(delegation_policy.principal_user_id);

      },

      // FieldValue -> (Field | Item)
      AccessPolicyResourceType::FieldValue => {

        let Some(field_value_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::FieldValue));

        };

        hierarchy.push((AccessPolicyResourceType::FieldValue, Some(field_value_id)));

        let field_value = match FieldValue::get_by_id(&field_value_id, database_pool).await {

          Ok(field_value) => field_value,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::FieldValue, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match field_value.parent_resource_type {

          FieldValueParentResourceType::Field => {
            
            selected_resource_type = AccessPolicyResourceType::Field;
            selected_resource_id = field_value.parent_field_id;

          },

          FieldValueParentResourceType::Item => {

            selected_resource_type = AccessPolicyResourceType::Item;
            selected_resource_id = field_value.parent_item_id;

          }

        };

      },

      // Field -> (Workspace | Project)
      AccessPolicyResourceType::Field => {

        let Some(field_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Field));

        };

        hierarchy.push((AccessPolicyResourceType::Field, Some(field_id)));

        let field = match Field::get_by_id(&field_id, database_pool).await {

          Ok(field) => field,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Field, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Project;
        selected_resource_id = Some(field.parent_project_id);

      },

      // FieldChoice -> Field
      AccessPolicyResourceType::FieldChoice => {

        let Some(field_choice_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::FieldChoice));

        };

        hierarchy.push((AccessPolicyResourceType::FieldChoice, Some(field_choice_id)));

        let field_choice = match FieldChoice::get_by_id(&field_choice_id, database_pool).await {

          Ok(field_choice) => field_choice,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::FieldChoice, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Field;
        selected_resource_id = Some(field_choice.field_id);

      },

      // Group -> Server
      AccessPolicyResourceType::Group => {

        let Some(group_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

        };

        hierarchy.push((AccessPolicyResourceType::Group, Some(group_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // HTTPTransaction -> Server
      AccessPolicyResourceType::HTTPTransaction => {

        let Some(http_transaction_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::HTTPTransaction));

        };

        hierarchy.push((AccessPolicyResourceType::HTTPTransaction, Some(http_transaction_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },
      
      // Server
      AccessPolicyResourceType::Server => break,

      // Item -> Project
      AccessPolicyResourceType::Item => {

        let Some(scoped_item_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Item));

        };

        hierarchy.push((AccessPolicyResourceType::Item, Some(scoped_item_id)));

        let item = match Item::get_by_id(&scoped_item_id, database_pool).await {

          Ok(item) => item,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Item, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Project;
        selected_resource_id = Some(item.parent_project_id);

      },

      // ItemConnection -> Item + Item
      AccessPolicyResourceType::ItemConnection => {

        return Err(ResourceHierarchyError::MultipleOwnersError(AccessPolicyResourceType::ItemConnection));

      },

      // ItemConnectionType -> (Project | Workspace)
      AccessPolicyResourceType::ItemConnectionType => {

        let Some(item_connection_type_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ItemConnectionType));

        };

        hierarchy.push((AccessPolicyResourceType::ItemConnectionType, Some(item_connection_type_id)));

        let item_connection_type = match ItemConnectionType::get_by_id(&item_connection_type_id, database_pool).await {

          Ok(item_connection_type) => item_connection_type,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::ItemConnectionType, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };
        
        match item_connection_type.parent_resource_type {

          ItemConnectionTypeParentResourceType::Project => {

            let Some(project_id) = item_connection_type.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

            };

            selected_resource_type = AccessPolicyResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          ItemConnectionTypeParentResourceType::Workspace => {

            let Some(workspace_id) = item_connection_type.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // Membership -> (Group | Role)
      AccessPolicyResourceType::Membership => {

        let Some(role_membership_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Membership));

        };

        hierarchy.push((AccessPolicyResourceType::Membership, Some(role_membership_id)));

        let membership = match Membership::get_by_id(&role_membership_id, database_pool).await {

          Ok(membership) => membership,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Membership, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match membership.parent_resource_type {

          MembershipParentResourceType::Group => {

            let Some(group_id) = membership.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

            };

            selected_resource_type = AccessPolicyResourceType::Group;
            selected_resource_id = Some(group_id);

          },

          MembershipParentResourceType::Role => {

            let Some(role_id) = membership.parent_role_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Role));

            };

            selected_resource_type = AccessPolicyResourceType::Role;
            selected_resource_id = Some(role_id);

          }

        }

      }

      // MembershipInvitation -> (Group | Role)
      AccessPolicyResourceType::MembershipInvitation => {

        let Some(membership_invitation_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::MembershipInvitation));

        };

        hierarchy.push((AccessPolicyResourceType::MembershipInvitation, Some(membership_invitation_id)));

        let membership_invitation = match MembershipInvitation::get_by_id(&membership_invitation_id, database_pool).await {

          Ok(membership_invitation) => membership_invitation,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::MembershipInvitation, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match membership_invitation.parent_resource_type {

          MembershipParentResourceType::Group => {

            let Some(group_id) = membership_invitation.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

            };

            selected_resource_type = AccessPolicyResourceType::Group;
            selected_resource_id = Some(group_id);

          },

          MembershipParentResourceType::Role => {

            let Some(role_id) = membership_invitation.parent_role_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Role));

            };

            selected_resource_type = AccessPolicyResourceType::Role;
            selected_resource_id = Some(role_id);

          }

        }

      },

      // Milestone -> (Project | Workspace)
      AccessPolicyResourceType::Milestone => {

        let Some(milestone_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Milestone));

        };

        hierarchy.push((AccessPolicyResourceType::Milestone, Some(milestone_id)));

        let milestone = match Milestone::get_by_id(&milestone_id, database_pool).await {

          Ok(milestone) => milestone,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Milestone, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match milestone.parent_resource_type {

          MilestoneParentResourceType::Project => {

            let Some(project_id) = milestone.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

            };

            selected_resource_type = AccessPolicyResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          MilestoneParentResourceType::Workspace => {

            let Some(workspace_id) = milestone.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // OAuthAuthorization -> Server
      AccessPolicyResourceType::OAuthAuthorization => {

        let Some(oauth_authorization_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::OAuthAuthorization));

        };

        hierarchy.push((AccessPolicyResourceType::OAuthAuthorization, Some(oauth_authorization_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // Project -> Workspace
      AccessPolicyResourceType::Project => {

        let Some(scoped_project_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

        };

        hierarchy.push((AccessPolicyResourceType::Project, Some(scoped_project_id)));

        let project = match Project::get_by_id(&scoped_project_id, database_pool).await {

          Ok(project) => project,
          
          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Project, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Workspace;
        selected_resource_id = Some(project.workspace_id);

      },

      // Role -> (Project | Workspace | Group | Server)
      AccessPolicyResourceType::Role => {

        let Some(scoped_role_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Role));

        };

        hierarchy.push((AccessPolicyResourceType::Role, Some(scoped_role_id)));

        let role = match Role::get_by_id(&scoped_role_id, database_pool).await {

          Ok(role) => role,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Role, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match role.parent_resource_type {

          RoleParentResourceType::Server => {

            selected_resource_type = AccessPolicyResourceType::Server;
            selected_resource_id = None;

          },

          RoleParentResourceType::Workspace => {

            let Some(workspace_id) = role.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          RoleParentResourceType::Project => {

            let Some(project_id) = role.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

            };

            selected_resource_type = AccessPolicyResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          RoleParentResourceType::Group => {

            let Some(group_id) = role.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

            };

            selected_resource_type = AccessPolicyResourceType::Group;
            selected_resource_id = Some(group_id);

          }

        }

      },

      // ServerLogEntry -> Server
      AccessPolicyResourceType::ServerLogEntry => {

        let Some(scoped_server_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ServerLogEntry));

        };

        hierarchy.push((AccessPolicyResourceType::ServerLogEntry, Some(scoped_server_log_entry_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // Session -> User
      AccessPolicyResourceType::Session => {

        let Some(scoped_session_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Session));

        };

        hierarchy.push((AccessPolicyResourceType::Session, Some(scoped_session_id)));

        let session = match Session::get_by_id(&scoped_session_id, database_pool).await {

          Ok(role_membership) => role_membership,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Session, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::User;
        selected_resource_id = Some(session.user_id);

      },

      // User -> Server
      AccessPolicyResourceType::User => {

        let Some(scoped_user_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

        };

        hierarchy.push((AccessPolicyResourceType::User, Some(scoped_user_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      },

      // View -> (Project | Workspace)
      AccessPolicyResourceType::View => {

        let Some(scoped_view_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::View));

        };

        hierarchy.push((AccessPolicyResourceType::View, Some(scoped_view_id)));

        let view = match crate::resources::view::View::get_by_id(&scoped_view_id, database_pool).await {

          Ok(view) => view,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::View, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match view.parent_resource_type {

          crate::resources::view::ViewParentResourceType::Project => {

            let Some(project_id) = view.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

            };

            selected_resource_type = AccessPolicyResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          crate::resources::view::ViewParentResourceType::Workspace => {

            let Some(workspace_id) = view.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // Workspace -> Server
      AccessPolicyResourceType::Workspace => {

        let Some(scoped_workspace_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

        };

        hierarchy.push((AccessPolicyResourceType::Workspace, Some(scoped_workspace_id)));

        selected_resource_type = AccessPolicyResourceType::Server;
        selected_resource_id = None;

      }

    }
    
  }

  hierarchy.push((AccessPolicyResourceType::Server, None));

  return Ok(hierarchy);

}

pub async fn get_all_hierarchies(scoped_resource_type: &AccessPolicyResourceType, scoped_resource_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Vec<ResourceHierarchy>, ResourceHierarchyError> {

  let mut hierarchies: Vec<ResourceHierarchy> = Vec::new();

  match scoped_resource_type {

    AccessPolicyResourceType::ItemConnection => {

      let Some(&scoped_item_id) = scoped_resource_id else {

        return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Item));

      };

      let item_connection = ItemConnection::get_by_id(&scoped_item_id, database_pool).await?;

      let mut inward_hierarchy = get_hierarchy(&AccessPolicyResourceType::Item, Some(&item_connection.inward_item_id), &database_pool).await?;
      let mut outward_hierarchy = get_hierarchy(&AccessPolicyResourceType::Item, Some(&item_connection.outward_item_id), &database_pool).await?;
      inward_hierarchy.insert(0, (AccessPolicyResourceType::ItemConnection, Some(scoped_item_id)));
      outward_hierarchy.insert(0, (AccessPolicyResourceType::ItemConnection, Some(scoped_item_id)));
      hierarchies.push(inward_hierarchy);
      hierarchies.push(outward_hierarchy);

    }

    scoped_resource_type => {

      let hierarchy = get_hierarchy(scoped_resource_type, scoped_resource_id, database_pool).await?;
      hierarchies.push(hierarchy);

    }

  }

  return Ok(hierarchies);

}

/// Returns a list of access policies based on a hierarchy.
pub async fn list_access_policies_by_hierarchy(principal: &PrincipalWithID, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, database_pool: &deadpool_postgres::Pool) -> Result<Vec<AccessPolicy>, ResourceError> {

  let mut query_clauses: Vec<String> = Vec::new();

  for (resource_type, resource_id) in resource_hierarchy {

    if *resource_type == AccessPolicyResourceType::Server {

      query_clauses.push(format!("scoped_resource_type = 'Server'"));
      continue;

    }

    let resource_id = match resource_id {

      Some(resource_id) => resource_id,

      None => {
        
        let error_string = match resource_type {

          AccessPolicyResourceType::AccessPolicy => "An access policy ID must be provided.",
          AccessPolicyResourceType::Action => "An action ID must be provided.",
          AccessPolicyResourceType::ActionLogEntry => "An action log entry ID must be provided.",
          AccessPolicyResourceType::App => "An app ID must be provided.",
          AccessPolicyResourceType::AppAuthorization => "An app authorization ID must be provided.",
          AccessPolicyResourceType::AppAuthorizationCredential => "An app authorization credential ID must be provided.",
          AccessPolicyResourceType::AppCredential => "An app credential ID must be provided.",
          AccessPolicyResourceType::Configuration => "A configuration ID must be provided.",
          AccessPolicyResourceType::DelegationPolicy => "A delegation policy ID must be provided.",
          AccessPolicyResourceType::Field => "A field ID must be provided.",
          AccessPolicyResourceType::FieldChoice => "A field choice ID must be provided.",
          AccessPolicyResourceType::FieldValue => "A field value ID must be provided.",
          AccessPolicyResourceType::Group => "A group ID must be provided.",
          AccessPolicyResourceType::HTTPTransaction => "An HTTP transaction ID must be provided.",
          AccessPolicyResourceType::Server => "An server ID must be provided.", // Huh??
          AccessPolicyResourceType::Item => "An item ID must be provided.",
          AccessPolicyResourceType::ItemConnection => "An item connection ID must be provided.",
          AccessPolicyResourceType::ItemConnectionType => "An item connection type ID must be provided.",
          AccessPolicyResourceType::Membership => "A membership ID must be provided.",
          AccessPolicyResourceType::MembershipInvitation => "A membership invitation ID must be provided.",
          AccessPolicyResourceType::Milestone => "A milestone ID must be provided.",
          AccessPolicyResourceType::OAuthAuthorization => "An OAuth authorization ID must be provided.",
          AccessPolicyResourceType::Project => "A project ID must be provided.",
          AccessPolicyResourceType::Role => "A role ID must be provided.",
          AccessPolicyResourceType::ServerLogEntry => "A server log entry ID must be provided.",
          AccessPolicyResourceType::Session => "A session ID must be provided.",
          AccessPolicyResourceType::User => "A user ID must be provided.",
          AccessPolicyResourceType::View => "A view ID must be provided.",
          AccessPolicyResourceType::Workspace => "A workspace ID must be provided."

        };

        return Err(ResourceError::HierarchyResourceIDMissingError(error_string.to_string()));

      }

    };

    let resource_id_as_quote_literal = quote_literal(&format!("{}", resource_id));
    match resource_type {

      AccessPolicyResourceType::AccessPolicy => query_clauses.push(format!("scoped_access_policy_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Action => query_clauses.push(format!("scoped_action_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::ActionLogEntry => query_clauses.push(format!("scoped_action_log_entry_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::App => query_clauses.push(format!("scoped_app_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::AppAuthorization => query_clauses.push(format!("scoped_app_authorization_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::AppAuthorizationCredential => query_clauses.push(format!("scoped_app_authorization_credential_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::AppCredential => query_clauses.push(format!("scoped_app_credential_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Configuration => query_clauses.push(format!("scoped_configuration_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::DelegationPolicy => query_clauses.push(format!("scoped_delegation_policy_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Field => query_clauses.push(format!("scoped_field_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::FieldChoice => query_clauses.push(format!("scoped_field_choice_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::FieldValue => query_clauses.push(format!("scoped_field_value_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Group => query_clauses.push(format!("scoped_group_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::HTTPTransaction => query_clauses.push(format!("scoped_http_transaction_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Item => query_clauses.push(format!("scoped_item_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::ItemConnection => query_clauses.push(format!("scoped_item_connection_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::ItemConnectionType => query_clauses.push(format!("scoped_item_connection_type_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Membership => query_clauses.push(format!("scoped_membership_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::MembershipInvitation => query_clauses.push(format!("scoped_membership_invitation_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Milestone => query_clauses.push(format!("scoped_milestone_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::OAuthAuthorization => query_clauses.push(format!("scoped_oauth_authorization_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Project => query_clauses.push(format!("scoped_project_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Role => query_clauses.push(format!("scoped_role_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Server => {},
      AccessPolicyResourceType::ServerLogEntry => query_clauses.push(format!("scoped_server_log_entry_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Session => query_clauses.push(format!("scoped_session_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::User => query_clauses.push(format!("scoped_user_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::View => query_clauses.push(format!("scoped_view_id = {}", resource_id_as_quote_literal)),
      AccessPolicyResourceType::Workspace => query_clauses.push(format!("scoped_workspace_id = {}", resource_id_as_quote_literal))

    }

  }

  // This will turn the query into something like:
  // action_id = $1 AND (scoped_resource_type = 'Server' OR scoped_workspace_id = $2 OR scoped_project_id = $3 OR scoped_milestone_id = $4 OR scoped_item_id = $5)
  let principal_clause = match principal {

    PrincipalWithID::User(user_id) => format!("principal_user_id = '{}'", user_id),
    PrincipalWithID::Group(group_id) => format!("principal_group_id = '{}'", group_id),
    PrincipalWithID::Role(role_id) => format!("principal_role_id = '{}'", role_id),
    PrincipalWithID::App(app_id) => format!("principal_app_id = '{}'", app_id)

  };
  let mut query_filter = String::new();
  query_filter.push_str(format!("{} AND action_id = {} AND (", principal_clause, quote_literal(&action_id.to_string())).as_str());
  for i in 0..query_clauses.len() {

    if i > 0 {

      query_filter.push_str(" OR ");

    }

    query_filter.push_str(&query_clauses[i]);

  }
  query_filter.push_str(")");
  
  let access_policies = AccessPolicy::list(&query_filter, database_pool, None).await?;

  return Ok(access_policies);

}

pub async fn verify_permissions(principal: &PrincipalWithID, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, minimum_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceHierarchyError> {

  let relevant_access_policies = list_access_policies_by_hierarchy(principal, action_id, resource_hierarchy, database_pool).await?;
  let deepest_access_policy = match relevant_access_policies.first() {

    Some(access_policy) => access_policy,

    None => return Err(ResourceHierarchyError::ForbiddenError {
      principal: principal.clone(),
      action_id: action_id.to_string(),
      minimum_permission_level: minimum_permission_level.clone(),
      actual_permission_level: ActionPermissionLevel::None
    })

  };

  if &deepest_access_policy.permission_level < minimum_permission_level {

    return Err(ResourceHierarchyError::ForbiddenError {
      principal: principal.clone(),
      action_id: action_id.to_string(),
      minimum_permission_level: minimum_permission_level.clone(),
      actual_permission_level: deepest_access_policy.permission_level
    });

  }

  return Ok(());

}
