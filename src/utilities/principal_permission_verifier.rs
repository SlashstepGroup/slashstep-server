use thiserror::Error;
use uuid::Uuid;

use crate::resources::{ResourceError, access_policy::{AccessPolicy, AccessPolicyPermissionLevel, Principal, ResourceHierarchy}};

#[derive(Debug, Error)]
pub enum PrincipalPermissionVerifierError {

  #[error("The principal does not have the required permissions to perform the action \"{action_id}\".")]
  ForbiddenError {
    principal: Principal,
    action_id: String,
    minimum_permission_level: AccessPolicyPermissionLevel,
    actual_permission_level: AccessPolicyPermissionLevel
  },

  #[error(transparent)]
  ResourceError(#[from] ResourceError)
}

pub struct PrincipalPermissionVerifier;

impl PrincipalPermissionVerifier {

  pub async fn verify_permissions(principal: &Principal, action_id: &Uuid, resource_hierarchy: &ResourceHierarchy, minimum_permission_level: &AccessPolicyPermissionLevel, database_pool: &deadpool_postgres::Pool) -> Result<(), PrincipalPermissionVerifierError> {

    let relevant_access_policies = AccessPolicy::list_by_hierarchy(principal, action_id, resource_hierarchy, database_pool).await?;
    let deepest_access_policy = match relevant_access_policies.first() {

      Some(access_policy) => access_policy,

      None => return Err(PrincipalPermissionVerifierError::ForbiddenError {
        principal: principal.clone(),
        action_id: action_id.to_string(),
        minimum_permission_level: minimum_permission_level.clone(),
        actual_permission_level: AccessPolicyPermissionLevel::None
      })

    };

    if &deepest_access_policy.permission_level < minimum_permission_level {

      return Err(PrincipalPermissionVerifierError::ForbiddenError {
        principal: principal.clone(),
        action_id: action_id.to_string(),
        minimum_permission_level: minimum_permission_level.clone(),
        actual_permission_level: deepest_access_policy.permission_level
      });

    }

    return Ok(());

  }

}