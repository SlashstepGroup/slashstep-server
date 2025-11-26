# Authenticating as a user
## Authenticating as a user using session tokens
Users use [sessions](/docs/resources/sessions.md) to authenticate in Slashstep Server. When a user successfully sends a request to create a session, Slashstep Server tells their browser to securely store a session token, which contains a session ID that links to the user. Slashstep Server uses this session token to authenticate the user.

> [!WARNING]
> Slashstep Group recommends only using session tokens for clients, and not for general-purpose third-party apps. Session tokens can give complete control over most aspects of the user. This is a risk for the user, but also for admins of resources that the user has access to.
>
> If you're developing an app, consider using app authorizations to only get access to what you need when you need it.

## Authenticating as a user using app authorization credentials
When apps are authorized on a user, the app assumes the identity of the user. For example, if a user wants to use a third-party client to create a project, the app associated with the client will likely impersonate the user. As long as the user has the permission to create projects, the app's request will succeed.