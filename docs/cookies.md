# Cookies and Sessions: Considerations for Testing and Mocking.

## SameSite
There are often redirects that pass from one web service to another, for example during an
authentication flow or when API's and web apps are configured as upstream services being a 
proxy or layers of proxies. The security of the information to be trusted and passed between
services has several where a bad actor can compromise any of these services.

The SameSite cookie property defines what cookies can be shared between services with the same 
hostname, across schemes and ports i.e. from https to https. Most recent browsers will not
transmit cookies from a https source to a http destination, when the SameSite property is 
strict. This is approach is recommended.  A cookie is not sent to an insecure origin from a 
secure context on a navigation. Because this cookie would have been sent across schemes on 
the same site, it was not sent. This behavior enhances the SameSite attribute’s protection 
of user data from request forgery by network attackers.

## Sessions
Sessions are treated differently especially between web apps and API apps. Web apps typically have 
static content or artifacts and end user state that is managed through a web server. When a user 
returns from a previously validated device/browser, they can continue where they left off 
in the most seamless and invisible way. Cookies and Query parameters are two approaches that 
end user devices and downstream services use to identify themselves. Query parameters are less 
common the of cookies more standardised and ubiquitous.

API consumers are responsible for managing their own state. Where an API consumer is required to 
co-ordinate the state of an upstream service it is generally poor design and tightly couples the consumer
to the API. In addition, manny API calls are stateless and depending solely on the inputs of the
call for the desired result. As a result API services can horizontally scaled without the complexity
in managing sessions and state as required by web apps.

## Considerations with API Gateways, Testing and Mocks

Naming conventions for Cookies and Headers is commonly not performed as an upfront design task, but
rather a task organically performed after hours if not days of problems tracking down weired and
undefined behaviours. 

When a number of upstream API services and or web services are placed behind a single proxy it 
becomes susceptible to a few problems in relation to `Cookies` : 
* Cookies with the same name are overwritten by my different upstream services.
* In testing there could be flows between a mix of http and https services and some cookies may be dropped.

Where `load balancing` across instances/targets of an upstream service will be intended, has the distribution 
algorithm been considered and its impact on the design of the service? 
* Is sharding or consistent hashing be required? 
* How important is the stickiness of consumer sessions?
* What are the capabilities of the gateway or load balancer?
* Are the API calls stateless or stateful?

Authentication facilitated through headers and cookies must use the same protocol and patterns between development 
testing using mock services and production infrastructure and patterns. In fact all data and API flow though follow
identical integration protocols. Examples of poor practice are:
* Using Basic Authentication as apposed to OAuth authentication flows.
* Using random text secrets rather than compliant JWT's
* Conventions for API keys or user authentication tokens should be consistent across application domains and portfolios.












