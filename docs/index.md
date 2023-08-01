# Openid-Whisperer

Sometimes you want to stand up an application fast, and you don't want to compromise on its design or access control. 
Openid-Whisperer provides a quick and efficient set of solutions where applications have a requirement for OpenID 1.0 
or Oauth 2.0 authentication and access control.

1. OpenID Identity Service run either standalone or as Docker container
2. Python OpenID class library
3. Flask OpenID blueprint
4. Customised or mock end user information claims
5. Sandbox for learning and experimenting

There are numerous opensource projects that offer specifications, patterns and solutions around OpenID 
authentication and authorisation. This project aims to take a lightweight approach with as complete functional flow and 
api coverage as possible. Some of the references that have been useful to this effort are:

* https://openid.net/developers/specs/
* https://auth0.com/docs/
* https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios
* https://github.com/AzureAD/microsoft-authentication-library-for-python

## [Considerations with Testing and Mocks](cookies.md)
Here you can find notes on considerations around how Cookies, Headers and Gateways impact on service design and testing.