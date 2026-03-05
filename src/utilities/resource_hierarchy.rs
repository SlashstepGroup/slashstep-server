use pg_escape::quote_literal;
use thiserror::Error;
use uuid::Uuid;

use crate::resources::{ResourceError, access_policy::{AccessPolicy, ResourceType, ActionPermissionLevel}, action::Action, app::{App, AppParentResourceType}, app_authorization::{AppAuthorization, AppAuthorizationAuthorizingResourceType}, app_authorization_credential::AppAuthorizationCredential, app_credential::AppCredential, field::Field, field_choice::FieldChoice, field_value::{FieldValue, FieldValueParentResourceType}, item::Item, item_connection::ItemConnection, item_connection_type::{ItemConnectionType, ItemConnectionTypeParentResourceType}, membership::{Membership, MembershipParentResourceType}, membership_invitation::MembershipInvitation, milestone::{Milestone, MilestoneParentResourceType}, project::Project, role::{Role, RoleParentResourceType}, session::Session};

pub type ResourceHierarchy = Vec<(ResourceType, Option<Uuid>)>;

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
  ScopedResourceIDMissingError(ResourceType),

  #[error("An ancestor resource of type {0} is required.")]
  OrphanedResourceError(ResourceType, ResourceHierarchy),

  #[error("{0} resources have multiple owners. Use the get_all_hierarchies() function to get all the resource hierarchies.")]
  MultipleOwnersError(ResourceType),

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

pub async fn get_hierarchy(scoped_resource_type: &ResourceType, scoped_resource_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<ResourceHierarchy, ResourceHierarchyError> {

  let mut hierarchy: ResourceHierarchy = vec![];
  let mut selected_resource_type: ResourceType = scoped_resource_type.clone();
  let mut selected_resource_id = scoped_resource_id.copied();
  
  loop {

    match selected_resource_type {

      // AccessPolicy -> (AccessPolicy | Action | ActionLogEntry | App | AppAuthorization | AppAuthorizationCredential | AppCredential | Configuration | DelegationPolicy | Field | FieldChoice | FieldValue | Group | HTTPTransaction | Item | ItemConnection | ItemConnectionType | Membership | MembershipInvitation | Milestone | OAuthAuthorization | Project | Role | ServerLogEntry | Session | User | View | Workspace)
      ResourceType::AccessPolicy => {

        let Some(access_policy_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::AccessPolicy));

        };

        hierarchy.push((ResourceType::AccessPolicy, Some(access_policy_id)));

        let access_policy = AccessPolicy::get_by_id(&access_policy_id, database_pool).await?;
        selected_resource_type = access_policy.scoped_resource_type;
        selected_resource_id = match access_policy.scoped_resource_type {
        
          ResourceType::AccessPolicy => access_policy.scoped_access_policy_id,
          ResourceType::Action => access_policy.scoped_action_id,
          ResourceType::ActionLogEntry => access_policy.scoped_action_log_entry_id,
          ResourceType::App => access_policy.scoped_app_id,
          ResourceType::AppAuthorization => access_policy.scoped_app_authorization_id,
          ResourceType::AppAuthorizationCredential => access_policy.scoped_app_authorization_credential_id,
          ResourceType::AppCredential => access_policy.scoped_app_credential_id,
          ResourceType::Configuration => access_policy.scoped_configuration_id,
          ResourceType::DelegationPolicy => access_policy.scoped_delegation_policy_id,
          ResourceType::Field => access_policy.scoped_field_id,
          ResourceType::FieldChoice => access_policy.scoped_field_choice_id,
          ResourceType::FieldValue => access_policy.scoped_field_value_id,
          ResourceType::Group => access_policy.scoped_group_id,
          ResourceType::HTTPTransaction => access_policy.scoped_http_transaction_id,
          ResourceType::Item => access_policy.scoped_item_id,
          ResourceType::ItemConnection => access_policy.scoped_item_connection_id,
          ResourceType::ItemConnectionType => access_policy.scoped_item_connection_type_id,
          ResourceType::Membership => access_policy.scoped_membership_id,
          ResourceType::MembershipInvitation => access_policy.scoped_membership_invitation_id,
          ResourceType::Milestone => access_policy.scoped_milestone_id,
          ResourceType::OAuthAuthorization => access_policy.scoped_oauth_authorization_id,
          ResourceType::Project => access_policy.scoped_project_id,
          ResourceType::Role => access_policy.scoped_role_id,
          ResourceType::Server => None,
          ResourceType::ServerLogEntry => access_policy.scoped_server_log_entry_id,
          ResourceType::Session => access_policy.scoped_session_id,
          ResourceType::User => access_policy.scoped_user_id,
          ResourceType::View => access_policy.scoped_view_id,
          ResourceType::Workspace => access_policy.scoped_workspace_id,

        }

      },

      // Action -> (App | Server)
      ResourceType::Action => {

        let Some(action_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Action));

        };

        hierarchy.push((ResourceType::Action, Some(action_id)));

        let action = match Action::get_by_id(&action_id, database_pool).await {

          Ok(action) => action,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Action, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        if let Some(app_id) = action.parent_app_id {

          selected_resource_type = ResourceType::App;
          selected_resource_id = Some(app_id);

        } else {

          selected_resource_type = ResourceType::Server;
          selected_resource_id = None;

        }

      },

      // ActionLogEntry -> Server
      ResourceType::ActionLogEntry => {

        let Some(scoped_action_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::ActionLogEntry));

        };

        hierarchy.push((ResourceType::ActionLogEntry, Some(scoped_action_log_entry_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // App -> (Workspace | User | Server)
      ResourceType::App => {

        let Some(app_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::App));

        };

        hierarchy.push((ResourceType::App, Some(app_id)));

        let app = match App::get_by_id(&app_id, database_pool).await {

          Ok(app) => app,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::App, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match app.parent_resource_type {

          AppParentResourceType::Server => {

            selected_resource_type = ResourceType::Server;
            selected_resource_id = None;

          },

          AppParentResourceType::Workspace => {

            let Some(workspace_id) = app.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          AppParentResourceType::User => {

            let Some(user_id) = app.parent_user_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::User));

            };

            selected_resource_type = ResourceType::User;
            selected_resource_id = Some(user_id);

          }

        }

      },

      // AppAuthorization -> (User | Workspace | Server)
      ResourceType::AppAuthorization => {

        let Some(app_authorization_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::AppAuthorization));

        };

        hierarchy.push((ResourceType::AppAuthorization, Some(app_authorization_id)));

        let app_authorization = match AppAuthorization::get_by_id(&app_authorization_id, database_pool).await {

          Ok(app_authorization) => app_authorization,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::AppAuthorization, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match app_authorization.authorizing_resource_type {

          AppAuthorizationAuthorizingResourceType::Server => {

            selected_resource_type = ResourceType::Server;
            selected_resource_id = None;

          },

          AppAuthorizationAuthorizingResourceType::Project => {

            let Some(project_id) = app_authorization.authorizing_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

            };

            selected_resource_type = ResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          AppAuthorizationAuthorizingResourceType::Workspace => {

            let Some(workspace_id) = app_authorization.authorizing_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          AppAuthorizationAuthorizingResourceType::User => {

            let Some(user_id) = app_authorization.authorizing_user_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::User));

            };

            selected_resource_type = ResourceType::User;
            selected_resource_id = Some(user_id);

          }

        }

      },

      // AppAuthorizationCredential -> AppAuthorization
      ResourceType::AppAuthorizationCredential => {

        let Some(app_authorization_credential_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::AppAuthorizationCredential));

        };

        hierarchy.push((ResourceType::AppAuthorizationCredential, Some(app_authorization_credential_id)));

        let app_authorization_credential = match AppAuthorizationCredential::get_by_id(&app_authorization_credential_id, database_pool).await {

          Ok(app_authorization_credential) => app_authorization_credential,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::AppAuthorizationCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::AppAuthorization;
        selected_resource_id = Some(app_authorization_credential.app_authorization_id);

      },

      // AppCredential -> App
      ResourceType::AppCredential => {

        let Some(app_credential_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::AppCredential));

        };

        hierarchy.push((ResourceType::AppCredential, Some(app_credential_id)));

        let app_credential = match AppCredential::get_by_id(&app_credential_id, database_pool).await {

          Ok(app_credential) => app_credential,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::AppCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::App;
        selected_resource_id = Some(app_credential.app_id);

      },

      // Configuration -> Server
      ResourceType::Configuration => {

        let Some(configuration_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Configuration));

        };

        hierarchy.push((ResourceType::Configuration, Some(configuration_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // DelegationPolicy -> User
      ResourceType::DelegationPolicy => {

        let Some(delegation_policy_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::DelegationPolicy));

        };

        hierarchy.push((ResourceType::DelegationPolicy, Some(delegation_policy_id)));

        let delegation_policy = match crate::resources::delegation_policy::DelegationPolicy::get_by_id(&delegation_policy_id, database_pool).await {

          Ok(delegation_policy) => delegation_policy,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::DelegationPolicy, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::User;
        selected_resource_id = Some(delegation_policy.principal_user_id);

      },

      // FieldValue -> (Field | Item)
      ResourceType::FieldValue => {

        let Some(field_value_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::FieldValue));

        };

        hierarchy.push((ResourceType::FieldValue, Some(field_value_id)));

        let field_value = match FieldValue::get_by_id(&field_value_id, database_pool).await {

          Ok(field_value) => field_value,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::FieldValue, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match field_value.parent_resource_type {

          FieldValueParentResourceType::Field => {
            
            selected_resource_type = ResourceType::Field;
            selected_resource_id = field_value.parent_field_id;

          },

          FieldValueParentResourceType::Item => {

            selected_resource_type = ResourceType::Item;
            selected_resource_id = field_value.parent_item_id;

          }

        };

      },

      // Field -> (Workspace | Project)
      ResourceType::Field => {

        let Some(field_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Field));

        };

        hierarchy.push((ResourceType::Field, Some(field_id)));

        let field = match Field::get_by_id(&field_id, database_pool).await {

          Ok(field) => field,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Field, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::Project;
        selected_resource_id = Some(field.parent_project_id);

      },

      // FieldChoice -> Field
      ResourceType::FieldChoice => {

        let Some(field_choice_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::FieldChoice));

        };

        hierarchy.push((ResourceType::FieldChoice, Some(field_choice_id)));

        let field_choice = match FieldChoice::get_by_id(&field_choice_id, database_pool).await {

          Ok(field_choice) => field_choice,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::FieldChoice, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::Field;
        selected_resource_id = Some(field_choice.field_id);

      },

      // Group -> Server
      ResourceType::Group => {

        let Some(group_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Group));

        };

        hierarchy.push((ResourceType::Group, Some(group_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // HTTPTransaction -> Server
      ResourceType::HTTPTransaction => {

        let Some(http_transaction_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::HTTPTransaction));

        };

        hierarchy.push((ResourceType::HTTPTransaction, Some(http_transaction_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },
      
      // Server
      ResourceType::Server => break,

      // Item -> Project
      ResourceType::Item => {

        let Some(scoped_item_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Item));

        };

        hierarchy.push((ResourceType::Item, Some(scoped_item_id)));

        let item = match Item::get_by_id(&scoped_item_id, database_pool).await {

          Ok(item) => item,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Item, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::Project;
        selected_resource_id = Some(item.parent_project_id);

      },

      // ItemConnection -> Item + Item
      ResourceType::ItemConnection => {

        return Err(ResourceHierarchyError::MultipleOwnersError(ResourceType::ItemConnection));

      },

      // ItemConnectionType -> (Project | Workspace)
      ResourceType::ItemConnectionType => {

        let Some(item_connection_type_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::ItemConnectionType));

        };

        hierarchy.push((ResourceType::ItemConnectionType, Some(item_connection_type_id)));

        let item_connection_type = match ItemConnectionType::get_by_id(&item_connection_type_id, database_pool).await {

          Ok(item_connection_type) => item_connection_type,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::ItemConnectionType, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };
        
        match item_connection_type.parent_resource_type {

          ItemConnectionTypeParentResourceType::Project => {

            let Some(project_id) = item_connection_type.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

            };

            selected_resource_type = ResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          ItemConnectionTypeParentResourceType::Workspace => {

            let Some(workspace_id) = item_connection_type.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // Membership -> (Group | Role)
      ResourceType::Membership => {

        let Some(role_membership_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Membership));

        };

        hierarchy.push((ResourceType::Membership, Some(role_membership_id)));

        let membership = match Membership::get_by_id(&role_membership_id, database_pool).await {

          Ok(membership) => membership,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Membership, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match membership.parent_resource_type {

          MembershipParentResourceType::Group => {

            let Some(group_id) = membership.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Group));

            };

            selected_resource_type = ResourceType::Group;
            selected_resource_id = Some(group_id);

          },

          MembershipParentResourceType::Role => {

            let Some(role_id) = membership.parent_role_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Role));

            };

            selected_resource_type = ResourceType::Role;
            selected_resource_id = Some(role_id);

          }

        }

      }

      // MembershipInvitation -> (Group | Role)
      ResourceType::MembershipInvitation => {

        let Some(membership_invitation_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::MembershipInvitation));

        };

        hierarchy.push((ResourceType::MembershipInvitation, Some(membership_invitation_id)));

        let membership_invitation = match MembershipInvitation::get_by_id(&membership_invitation_id, database_pool).await {

          Ok(membership_invitation) => membership_invitation,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::MembershipInvitation, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match membership_invitation.parent_resource_type {

          MembershipParentResourceType::Group => {

            let Some(group_id) = membership_invitation.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Group));

            };

            selected_resource_type = ResourceType::Group;
            selected_resource_id = Some(group_id);

          },

          MembershipParentResourceType::Role => {

            let Some(role_id) = membership_invitation.parent_role_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Role));

            };

            selected_resource_type = ResourceType::Role;
            selected_resource_id = Some(role_id);

          }

        }

      },

      // Milestone -> (Project | Workspace)
      ResourceType::Milestone => {

        let Some(milestone_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Milestone));

        };

        hierarchy.push((ResourceType::Milestone, Some(milestone_id)));

        let milestone = match Milestone::get_by_id(&milestone_id, database_pool).await {

          Ok(milestone) => milestone,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Milestone, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match milestone.parent_resource_type {

          MilestoneParentResourceType::Project => {

            let Some(project_id) = milestone.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

            };

            selected_resource_type = ResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          MilestoneParentResourceType::Workspace => {

            let Some(workspace_id) = milestone.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // OAuthAuthorization -> Server
      ResourceType::OAuthAuthorization => {

        let Some(oauth_authorization_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::OAuthAuthorization));

        };

        hierarchy.push((ResourceType::OAuthAuthorization, Some(oauth_authorization_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // Project -> Workspace
      ResourceType::Project => {

        let Some(scoped_project_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

        };

        hierarchy.push((ResourceType::Project, Some(scoped_project_id)));

        let project = match Project::get_by_id(&scoped_project_id, database_pool).await {

          Ok(project) => project,
          
          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Project, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::Workspace;
        selected_resource_id = Some(project.workspace_id);

      },

      // Role -> (Project | Workspace | Group | Server)
      ResourceType::Role => {

        let Some(scoped_role_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Role));

        };

        hierarchy.push((ResourceType::Role, Some(scoped_role_id)));

        let role = match Role::get_by_id(&scoped_role_id, database_pool).await {

          Ok(role) => role,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Role, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match role.parent_resource_type {

          RoleParentResourceType::Server => {

            selected_resource_type = ResourceType::Server;
            selected_resource_id = None;

          },

          RoleParentResourceType::Workspace => {

            let Some(workspace_id) = role.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          RoleParentResourceType::Project => {

            let Some(project_id) = role.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

            };

            selected_resource_type = ResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          RoleParentResourceType::Group => {

            let Some(group_id) = role.parent_group_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Group));

            };

            selected_resource_type = ResourceType::Group;
            selected_resource_id = Some(group_id);

          }

        }

      },

      // ServerLogEntry -> Server
      ResourceType::ServerLogEntry => {

        let Some(scoped_server_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::ServerLogEntry));

        };

        hierarchy.push((ResourceType::ServerLogEntry, Some(scoped_server_log_entry_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // Session -> User
      ResourceType::Session => {

        let Some(scoped_session_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Session));

        };

        hierarchy.push((ResourceType::Session, Some(scoped_session_id)));

        let session = match Session::get_by_id(&scoped_session_id, database_pool).await {

          Ok(role_membership) => role_membership,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::Session, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        selected_resource_type = ResourceType::User;
        selected_resource_id = Some(session.user_id);

      },

      // User -> Server
      ResourceType::User => {

        let Some(scoped_user_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::User));

        };

        hierarchy.push((ResourceType::User, Some(scoped_user_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      },

      // View -> (Project | Workspace)
      ResourceType::View => {

        let Some(scoped_view_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::View));

        };

        hierarchy.push((ResourceType::View, Some(scoped_view_id)));

        let view = match crate::resources::view::View::get_by_id(&scoped_view_id, database_pool).await {

          Ok(view) => view,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(ResourceType::View, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match view.parent_resource_type {

          crate::resources::view::ViewParentResourceType::Project => {

            let Some(project_id) = view.parent_project_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Project));

            };

            selected_resource_type = ResourceType::Project;
            selected_resource_id = Some(project_id);

          },

          crate::resources::view::ViewParentResourceType::Workspace => {

            let Some(workspace_id) = view.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

            };

            selected_resource_type = ResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          }

        }

      },

      // Workspace -> Server
      ResourceType::Workspace => {

        let Some(scoped_workspace_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Workspace));

        };

        hierarchy.push((ResourceType::Workspace, Some(scoped_workspace_id)));

        selected_resource_type = ResourceType::Server;
        selected_resource_id = None;

      }

    }
    
  }

  hierarchy.push((ResourceType::Server, None));

  return Ok(hierarchy);

}

pub async fn get_all_hierarchies(scoped_resource_type: &ResourceType, scoped_resource_id: Option<&Uuid>, database_pool: &deadpool_postgres::Pool) -> Result<Vec<ResourceHierarchy>, ResourceHierarchyError> {

  let mut hierarchies: Vec<ResourceHierarchy> = Vec::new();

  match scoped_resource_type {

    ResourceType::ItemConnection => {

      let Some(&scoped_item_id) = scoped_resource_id else {

        return Err(ResourceHierarchyError::ScopedResourceIDMissingError(ResourceType::Item));

      };

      let item_connection = ItemConnection::get_by_id(&scoped_item_id, database_pool).await?;

      let mut inward_hierarchy = get_hierarchy(&ResourceType::Item, Some(&item_connection.inward_item_id), &database_pool).await?;
      let mut outward_hierarchy = get_hierarchy(&ResourceType::Item, Some(&item_connection.outward_item_id), &database_pool).await?;
      inward_hierarchy.insert(0, (ResourceType::ItemConnection, Some(scoped_item_id)));
      outward_hierarchy.insert(0, (ResourceType::ItemConnection, Some(scoped_item_id)));
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

pub async fn verify_permissions(principal: &PrincipalWithID, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, minimum_permission_level: &ActionPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), ResourceHierarchyError> {

  let database_client = database_pool.get().await?;
  let principal_type = match principal {

    PrincipalWithID::App(_) => "App",
    PrincipalWithID::User(_) => "User",
    PrincipalWithID::Group(_) => "Group",
    PrincipalWithID::Role(_) => "Role"

  };
  let principal_id = match principal {

    PrincipalWithID::App(app_id) => app_id,
    PrincipalWithID::User(user_id) => user_id,
    PrincipalWithID::Group(group_id) => group_id,
    PrincipalWithID::Role(role_id) => role_id

  };
  let permission_level = database_client.query_one("SELECT get_principal_permission_level($1, $2, $3, $4, $5)", &[
    &principal_type,
    &principal_id,
    &action_id
  ]).await?;
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
