# ARLAS-UMS

## What is it?
This module aims at adding a User Management System (UMS) to the ARLAS stack.  
UMS provides authentication (user login) and authorisation (permissions to access data and APIs) services to ARLAS components: server, WUI, hub, builder...  

The stack can be started with or without UMS. When started with, ARLAS can be connected to various "auth" platforms:
- [Auth0](https://auth0.com/)
- [Keycloak](https://www.keycloak.org/)
- ARLAS IDP (see below)

The platform to connect to is selected by the way of a specific **Policy Enforcer** which basically is a servlet request filter activated in backend components (server, persistence...).  

The open source ARLAS stack cannot be started with UMS activated. It is packaged with a "do nothing" policy enforcer.  
UMS is only available with ARLAS Enterprise, which includes the implementations required to communicate with the supported "auth" platforms.

This project is composed of 2 main components:
1. a set of implementations of ARLAS PolicyEnforcer (interface available in the ARLAS-server/arlas-commons module: `io.arlas.commons.rest.auth.PolicyEnforcer`)
   - Auth0 implementation (`io.arlas.ums.filter.impl.Auth0PolicyEnforcer`)
   - Keycloak implementation (`io.arlas.ums.filter.impl.KeycloakPolicyEnforcer`)
   - HTTP implementation (`io.arlas.ums.filter.impl.HTTPPolicyEnforcer`)
2. an IDP server

## Policy Enforcers
The policy enforcers are in the `arlas-ums-filer` module.  
The implementation to be activated must be defined in the backend component configuration:


| Environment variable    | configuration variable  | Default                                     | Possible values                                                                                                                                  |
|-------------------------|-------------------------|---------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| ARLAS_AUTH_POLICY_CLASS | arlas_auth_policy_class | io.arlas.commons.rest.auth.NoPolicyEnforcer | io.arlas.ums.filter.impl.Auth0PolicyEnforcer<br/>io.arlas.ums.filter.impl.KeycloakPolicyEnforcer<br/>io.arlas.ums.filter.impl.HTTPPolicyEnforcer |

Further configuration may be required depending on the chosen implementation:

| Environment variable         | configuration variable                 | Default                                                   | Policy enforcer |
|------------------------------|----------------------------------------|-----------------------------------------------------------|-----------------|
| ARLAS_AUTH_PUBLIC_URIS       | arlas_auth.public_uris                 | swagger.\*:\*                                             | All             |
| ARLAS_HEADER_USER            | arlas_auth.header_user                 | arlas-user                                                | All             |
| ARLAS_HEADER_GROUP           | arlas_auth.header_group                | arlas-groups                                              | All             |
| ARLAS_CLAIM_ROLES            | arlas_auth.claim_roles                 | http://arlas.io/roles                                     | All             |
| ARLAS_CLAIM_PERMISSIONS      | arlas_auth.claim_permissions           | http://arlas.io/permissions                               | All             |
| ARLAS_AUTH_CERT_URL          | arlas_auth.certificate_url             | none                                                      | Auth0           |
| ARLAS_AUTH_PERMISSION_URL    | arlas_auth.permission_url              | http://arlas-idp-server/arlas_idp_server/auth/permissions | HTTP            |
| ARLAS_AUTH_KEYCLOAK_REALM    | arlas_auth.keycloak.realm              | arlas                                                     | Keycloak        |
| ARLAS_AUTH_KEYCLOAK_URL      | arlas_auth.keycloak.auth-server-url    | http://keycloak:8080/auth                                 | Keycloak        |
| ARLAS_AUTH_KEYCLOAK_RESOURCE | arlas_auth.keycloak.resource           | arlas                                                     | Keycloak        |
| ARLAS_AUTH_KEYCLOAK_SECRET   | arlas_auth.keycloak.credentials.secret |                                                           | Keycloak        |


## IDP server
The IDP server provides authentication and authorization features that can be deployed with the ARLAS stack without the need to depend on a third party provider.  

### Concepts
TO BE CONTINUED
**Organisation**: a group of users who need to access Arlas. Usually of the same customer but not necessarily (users of Gisaïa or other customer can be invited in an organisation).
**Role**: 
**Permission**: 
**Session**: 

