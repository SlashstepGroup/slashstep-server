# Best practices for authentication
## Choosing the right authentication method
* Use [sessions](/docs/resources/session.md) for first-party, browser-based clients that are built for the end-user. Session cookies should be same-site, secure, and http-only.
* Use [app authorization credentials](/docs/resources/app-authorization-credentials.md) for apps that need to access resources that were granted via app authorizations. 
* Use [app credentials](/docs/resources/app-credential.md) for apps that need to authenticate as themselves and generate app authorization credentials.