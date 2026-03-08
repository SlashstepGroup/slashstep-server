# Slashstep Server contribution guide
## Issues
Before starting work, make sure there is a GitHub issue for your change.

## Style
### Routes
The REST API routes should be as close as possible to the path of routes that an end-user would use.

For example, if a route is something like `DELETE /access-policies/{access_policy_id}`, then do the following:
* Ensure that a folder named "access-policies" in the [`src/routes`](/src/routes) directory exists.
* Ensure that a file named "{access_policy_id}.rs" in the [`src/routes/access-policies`](/src/routes/access-policies) directory exists.
* Ensure that a [path attribute](https://doc.rust-lang.org/reference/items/modules.html#the-path-attribute) in [`src/routes/access-policies.rs`](/src/routes/access-policies.rs) file is used to import the "{access_policy_id}.rs" module.
* In the [`src/routes/access-policies/{access_policy_id}.rs`](/src/routes/access-policies/{access_policy_id}.rs) file, add a function that handles the DELETE method. Add your route to the router returned in the `get_router()` function.

## Tests
All tests should pass before merging a change into the `development` or `production` branches.