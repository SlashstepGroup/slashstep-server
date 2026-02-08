# REST API endpoints for access policies
## List access policies from all scopes
```
GET /access-policies
```

Returns a list of access policies. Authentication may be required if anonymous users lack the permission to use this endpoint.

### Headers
| Header name | Description | Required? |
| :- | :- | :- |
| `Content-Type` | Must be `application/json`. | Yes |

### Query parameters
| Query | Description | Required? |
| :- | :- | :- |
| `query` | A SlashstepQL query to filter and limit results. | Yes |
| `limit` | The maximum number of results to return. | No |

### Required permissions
* [`slashstep.accessPolicies.list`](/src/resources/AccessPolicy/README.md#slashstepaccesspolicieslist) on the server level.

### Status codes
| Status code | Description |
| :- | :- |
| 200 | Success. |
| 400 | There's something wrong with your request. Check the response body for more information. |
| 401 | Anonymous users don't have the required permissions to use this endpoint. Provide authenticaton and try again. |
| 403 | You don't have the required permissions to use this endpoint. Get permissions from the appropriate admin and try again. |
| 500 | An internal server error happened. Try again later. If the error persists, report it to your server admin or to the Slashstep Group. |

## Get an access policy by ID
| Method | Endpoint |
| :- | :- |
| GET | `/access-policies/:accessPolicyID` |

### Headers
None.

### Query parameters
TBA.

### Required permissions
* [`slashstep.accessPolicies.get`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesget) on the access policy level or inherited from a higher level.

## Update an access policy
| Method | Endpoint |
| :- | :- |
| PATCH | `/access-policies/:accessPolicyID` |

### Required permissions
* [`slashstep.accessPolicies.update`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesupdate) on the access policy level or inherited from a higher level.

## Delete an access policy
| Method | Endpoint |
| :- | :- |
| DELETE | `/access-policies/:accessPolicyID` |

### Required permissions
* [`slashstep.accessPolicies.delete`](/src/resources/AccessPolicy/README.md#slashstepaccesspoliciesdelete) on the access policy level or inherited from a higher level.