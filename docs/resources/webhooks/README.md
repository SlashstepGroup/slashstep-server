# Webhooks
**Webhooks** are resources that send POST requests to user-defined websites after an action happens on Slashstep Server. This can be helpful for extending Slashstep Server by listening for specific events, then doing actions that aren't handled directly by Slashstep. 

## Example use cases of webhooks
After getting an event from Slashstep Server, apps can handle it in many ways. Some that come to mind include:
* Letting the team know in a group chat after someone completes an item.
* Updating video game player reports after a ticket is dismissed.
* Triggering CI/CD pipelines after getting approval from reviewers.
* Send an onboarding email after a user signs in for the first time.

Webhooks let you know when something changes, letting you do whatever you want after that.

## Actions
| Name | Display name | Description |
| :- | :- | :- |
| `webhooks.get` | Get webhooks | Get specific webhooks on a particular scope. |
| `webhooks.list` | List webhooks | List webhooks on a particular scope. |
| `webhooks.create` | Create webhooks | Create webhooks on a particular scope. |
| `webhooks.update` | Update webhooks | Update webhooks on a particular scope. |
| `webhooks.delete` | Delete webhooks | Delete webhooks on a particular scope. |

## Configurations
| Name | Value type | Description | Default value |
| :- | :- | :- | :- |
| `webhooks.maximumActiveCount` | Number | The maximum amount of webhooks that can be active at a time on a given resource. | 100 |
| `webhooks.maximumCount` | Number | The maximum amount of webhooks that can be owned on a given resource. | |

## Restrictions
### Only specific resources can use webhooks
You can only create webhooks on the following resources:
* Apps
* Groups
* Projects
* Servers
* Users
* Workspaces

This restriction is to simplify the user experience.

### Admin permissions are required to add or remove webhook event listeners
Principals managing webhooks must have admin permission over actions that they want to monitor using webhooks. If a principal tries to remove an event listener and the principal doesn't have admin permission over the action of the event listener, then the principal cannot remove the event listener. 

Webhook event listeners require admin permissions to protect user security, as some actions may be considered privileged (i.e. any action that ends with ".get"). 

### Maximum active webhook counts per resource may be limited
By default, there can only be 100 maximum active webhooks per resource. This can be changed through the `webhooks.maximumActiveCount` configuration.

### Maximum total webhook counts per resource may be limited
By default, there is no restriction on how many webhooks that can be owned per resource. This can be changed through the `webhooks.maximumCount` configuration.
