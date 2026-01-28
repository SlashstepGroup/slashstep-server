use thiserror::Error;
use uuid::Uuid;

use crate::resources::{ResourceError, access_policy::AccessPolicyResourceType, action::Action, action_log_entry::ActionLogEntry, app::{App, AppParentResourceType}, app_authorization::{AppAuthorization, AppAuthorizationError, AppAuthorizationParentResourceType}, app_authorization_credential::{AppAuthorizationCredential, AppAuthorizationCredentialError}, app_credential::{AppCredential, AppCredentialError}, group::GroupError, group_membership::{GroupMembership, GroupMembershipError}, http_transaction::HTTPTransactionError, item::{Item, ItemError}, milestone::{Milestone, MilestoneError, MilestoneParentResourceType}, project::{Project, ProjectError}, role::{Role, RoleError, RoleParentResourceType}, role_memberships::{RoleMembership, RoleMembershipError}, server_log_entry::ServerLogEntryError, session::{Session, SessionError}, user::UserError, workspace::WorkspaceError};

pub type ResourceHierarchy = Vec<(AccessPolicyResourceType, Option<Uuid>)>;

#[derive(Debug, Error)]
pub enum ResourceHierarchyError {
  #[error("A scoped resource ID is required for the {0} resource type.")]
  ScopedResourceIDMissingError(AccessPolicyResourceType),

  #[error("An ancestor resource of type {0} is required.")]
  OrphanedResourceError(AccessPolicyResourceType, ResourceHierarchy),

  #[error(transparent)]
  ResourceError(#[from] ResourceError),

  #[error(transparent)]
  AppAuthorizationError(AppAuthorizationError),

  #[error(transparent)]
  AppAuthorizationCredentialError(AppAuthorizationCredentialError),

  #[error(transparent)]
  AppCredentialError(AppCredentialError),

  #[error(transparent)]
  GroupError(GroupError),

  #[error(transparent)]
  GroupMembershipError(GroupMembershipError),

  #[error(transparent)]
  HTTPTransactionError(HTTPTransactionError),

  #[error(transparent)]
  ItemError(ItemError),

  #[error(transparent)]
  MilestoneError(MilestoneError),

  #[error(transparent)]
  ProjectError(ProjectError),

  #[error(transparent)]
  RoleError(RoleError),

  #[error(transparent)]
  RoleMembershipError(RoleMembershipError),

  #[error(transparent)]
  ServerLogEntryError(ServerLogEntryError),

  #[error(transparent)]
  SessionError(SessionError),

  #[error(transparent)]
  UserError(UserError),

  #[error(transparent)]
  WorkspaceError(WorkspaceError)

}

pub async fn get_hierarchy(scoped_resource_type: &AccessPolicyResourceType, scoped_resource_id: &Option<Uuid>, postgres_client: &mut deadpool_postgres::Client) -> Result<ResourceHierarchy, ResourceHierarchyError> {

  let mut hierarchy: ResourceHierarchy = vec![];
  let mut selected_resource_type: AccessPolicyResourceType = scoped_resource_type.clone();
  let mut selected_resource_id = scoped_resource_id.clone();
  
  loop {

    match selected_resource_type {

      // Action -> (App | Instance)
      AccessPolicyResourceType::Action => {

        let Some(action_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Action));

        };

        hierarchy.push((AccessPolicyResourceType::Action, Some(action_id)));

        let action = match Action::get_by_id(&action_id, postgres_client).await {

          Ok(action) => action,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Action, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        if let Some(app_id) = action.app_id {

          selected_resource_type = AccessPolicyResourceType::App;
          selected_resource_id = Some(app_id);

        } else {

          selected_resource_type = AccessPolicyResourceType::Instance;
          selected_resource_id = None;

        }

      },

      // ActionLogEntry -> Action
      AccessPolicyResourceType::ActionLogEntry => {

        let Some(scoped_action_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ActionLogEntry));

        };

        hierarchy.push((AccessPolicyResourceType::ActionLogEntry, Some(scoped_action_log_entry_id)));

        let action_log_entry = match ActionLogEntry::get_by_id(&scoped_action_log_entry_id, postgres_client).await {

          Ok(action_log_entry) => action_log_entry,

          Err(error) => return Err(ResourceHierarchyError::ResourceError(error))

        };

        selected_resource_type = AccessPolicyResourceType::Action;
        selected_resource_id = Some(action_log_entry.action_id);

      },

      // App -> (Workspace | User | Instance)
      AccessPolicyResourceType::App => {

        let Some(app_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::App));

        };

        hierarchy.push((AccessPolicyResourceType::App, Some(app_id)));

        let app = match App::get_by_id(&app_id, postgres_client).await {

          Ok(app) => app,

          Err(error) => match error {

            ResourceError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::App, hierarchy)),

            _ => return Err(ResourceHierarchyError::ResourceError(error))

          }

        };

        match app.parent_resource_type {

          AppParentResourceType::Instance => {

            selected_resource_type = AccessPolicyResourceType::Instance;
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

      // AppAuthorization -> (User | Workspace | Instance)
      AccessPolicyResourceType::AppAuthorization => {

        let Some(app_authorization_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::AppAuthorization));

        };

        hierarchy.push((AccessPolicyResourceType::AppAuthorization, Some(app_authorization_id)));

        let app_authorization = match AppAuthorization::get_by_id(&app_authorization_id, postgres_client).await {

          Ok(app_authorization) => app_authorization,

          Err(error) => match error {

            AppAuthorizationError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorization, hierarchy)),

            _ => return Err(ResourceHierarchyError::AppAuthorizationError(error))

          }

        };

        match app_authorization.parent_resource_type {

          AppAuthorizationParentResourceType::Instance => {

            selected_resource_type = AccessPolicyResourceType::Instance;
            selected_resource_id = None;

          },

          AppAuthorizationParentResourceType::Workspace => {

            let Some(workspace_id) = app_authorization.parent_workspace_id else {

              return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

            };

            selected_resource_type = AccessPolicyResourceType::Workspace;
            selected_resource_id = Some(workspace_id);

          },

          AppAuthorizationParentResourceType::User => {

            let Some(user_id) = app_authorization.parent_user_id else {

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

        let app_authorization_credential = match AppAuthorizationCredential::get_by_id(&app_authorization_credential_id, postgres_client).await {

          Ok(app_authorization_credential) => app_authorization_credential,

          Err(error) => match error {

            AppAuthorizationCredentialError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppAuthorizationCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::AppAuthorizationCredentialError(error))

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

        let app_credential = match AppCredential::get_by_id(&app_credential_id, postgres_client).await {

          Ok(app_credential) => app_credential,

          Err(error) => match error {

            AppCredentialError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::AppCredential, hierarchy)),

            _ => return Err(ResourceHierarchyError::AppCredentialError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::App;
        selected_resource_id = Some(app_credential.app_id);

      },

      // Group -> Instance
      AccessPolicyResourceType::Group => {

        let Some(group_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Group));

        };

        hierarchy.push((AccessPolicyResourceType::Group, Some(group_id)));

        selected_resource_type = AccessPolicyResourceType::Instance;
        selected_resource_id = None;

      },

      // GroupMembership -> Group
      AccessPolicyResourceType::GroupMembership => {

        let Some(group_membership_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::GroupMembership));

        };

        hierarchy.push((AccessPolicyResourceType::GroupMembership, Some(group_membership_id)));

        let group_membership = match GroupMembership::get_by_id(&group_membership_id, postgres_client).await {

          Ok(group_membership) => group_membership,

          Err(error) => match error {

            GroupMembershipError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::GroupMembership, hierarchy)),

            _ => return Err(ResourceHierarchyError::GroupMembershipError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Group;
        selected_resource_id = Some(group_membership.group_id);

      },

      // HTTPTransaction -> Instance
      AccessPolicyResourceType::HTTPTransaction => {

        let Some(http_transaction_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::HTTPTransaction));

        };

        hierarchy.push((AccessPolicyResourceType::HTTPTransaction, Some(http_transaction_id)));

        selected_resource_type = AccessPolicyResourceType::Instance;
        selected_resource_id = None;

      },
      
      // Instance
      AccessPolicyResourceType::Instance => break,

      // Item -> Project
      AccessPolicyResourceType::Item => {

        let Some(scoped_item_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Item));

        };

        hierarchy.push((AccessPolicyResourceType::Item, Some(scoped_item_id)));

        let item = match Item::get_by_id(&scoped_item_id, postgres_client).await {

          Ok(item) => item,

          Err(error) => match error {

            ItemError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Item, hierarchy)),

            _ => return Err(ResourceHierarchyError::ItemError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Project;
        selected_resource_id = Some(item.project_id);

      },

      // Milestone -> (Project | Workspace)
      AccessPolicyResourceType::Milestone => {

        let Some(milestone_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Milestone));

        };

        hierarchy.push((AccessPolicyResourceType::Milestone, Some(milestone_id)));

        let milestone = match Milestone::get_by_id(&milestone_id, postgres_client).await {

          Ok(milestone) => milestone,

          Err(error) => match error {

            MilestoneError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Milestone, hierarchy)),

            _ => return Err(ResourceHierarchyError::MilestoneError(error))

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

      // Project -> Workspace
      AccessPolicyResourceType::Project => {

        let Some(scoped_project_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Project));

        };

        hierarchy.push((AccessPolicyResourceType::Project, Some(scoped_project_id)));

        let project = match Project::get_by_id(&scoped_project_id, postgres_client).await {

          Ok(project) => project,
          
          Err(error) => match error {

            ProjectError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Project, hierarchy)),

            _ => return Err(ResourceHierarchyError::ProjectError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Workspace;
        selected_resource_id = Some(project.workspace_id);

      },

      // Role -> (Project | Workspace | Group | Instance)
      AccessPolicyResourceType::Role => {

        let Some(scoped_role_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Role));

        };

        hierarchy.push((AccessPolicyResourceType::Role, Some(scoped_role_id)));

        let role = match Role::get_by_id(&scoped_role_id, postgres_client).await {

          Ok(role) => role,

          Err(error) => match error {

            RoleError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Role, hierarchy)),

            _ => return Err(ResourceHierarchyError::RoleError(error))

          }

        };

        match role.parent_resource_type {

          RoleParentResourceType::Instance => {

            selected_resource_type = AccessPolicyResourceType::Instance;
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

      // RoleMembership -> Role
      AccessPolicyResourceType::RoleMembership => {

        let Some(role_membership_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::RoleMembership));

        };

        hierarchy.push((AccessPolicyResourceType::RoleMembership, Some(role_membership_id)));

        let role_membership = match RoleMembership::get_by_id(&role_membership_id, postgres_client).await {

          Ok(role_membership) => role_membership,

          Err(error) => match error {

            RoleMembershipError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::RoleMembership, hierarchy)),

            _ => return Err(ResourceHierarchyError::RoleMembershipError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::Role;
        selected_resource_id = Some(role_membership.role_id);

      }

      // ServerLogEntry -> Instance
      AccessPolicyResourceType::ServerLogEntry => {

        let Some(scoped_server_log_entry_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::ServerLogEntry));

        };

        hierarchy.push((AccessPolicyResourceType::ServerLogEntry, Some(scoped_server_log_entry_id)));

        selected_resource_type = AccessPolicyResourceType::Instance;
        selected_resource_id = None;

      },

      // Session -> User
      AccessPolicyResourceType::Session => {

        let Some(scoped_session_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Session));

        };

        hierarchy.push((AccessPolicyResourceType::Session, Some(scoped_session_id)));

        let session = match Session::get_by_id(&scoped_session_id, postgres_client).await {

          Ok(role_membership) => role_membership,

          Err(error) => match error {

            SessionError::NotFoundError(_) => return Err(ResourceHierarchyError::OrphanedResourceError(AccessPolicyResourceType::Session, hierarchy)),

            _ => return Err(ResourceHierarchyError::SessionError(error))

          }

        };

        selected_resource_type = AccessPolicyResourceType::User;
        selected_resource_id = Some(session.user_id);

      },

      // User -> Instance
      AccessPolicyResourceType::User => {

        let Some(scoped_user_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::User));

        };

        hierarchy.push((AccessPolicyResourceType::User, Some(scoped_user_id)));

      },

      // Workspace -> Instance
      AccessPolicyResourceType::Workspace => {

        let Some(scoped_workspace_id) = selected_resource_id else {

          return Err(ResourceHierarchyError::ScopedResourceIDMissingError(AccessPolicyResourceType::Workspace));

        };

        hierarchy.push((AccessPolicyResourceType::Workspace, Some(scoped_workspace_id)));

      }

    }
    
  }

  hierarchy.push((AccessPolicyResourceType::Instance, None));

  return Ok(hierarchy);

}