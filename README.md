# Beyond Identity ForgeRock Installation Guide

This guide details the steps required to configure Beyond Identity as a passwordless authentication solution for your ForgeRock using the ForgeRock OIDC node.
 
## Prerequisites
This integration relies on the ForgeRock OIDC Node which is available in AM6.0 or greater.

## Configuration

### Step 1: Obtain configuration values from Beyond Identity

Your Beyond Identity Solutions Engineer will provide the following information: 

- OIDC Client ID
- OIDC Client Secret

Please contact help@beyondidentity.com for more information. 

### Step 2: Configuring an OIDC Node

1. Create or modify an existing tree, adding a node of type OpenID Connect. 


2. Enter the following values for each configuration option in the OpenID Connect Node:

| Name                                | Value                                                                                                              |
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Authentication Endpoint URL.        | https://auth.byndid.com/authorize                                                                                  |
| Access Token Endpoint URL           | https://auth.byndid.com/token                                                                                      |
| User Profile Service URL            | Leave empty                                                                                                        |
| OAuth Scopes                        | openid                                                                                                             |
| Redirect URL                        | Varies based on your environment. Typically:  https://<forgerock-domain>/openam/?realm=<REALM>&service=<AUTH_TREE> |
| Social Provider                     | Beyond Identity                                                                                                    |
| Auth ID Key                         | sub                                                                                                                |
| Use Basic Auth                      | enabled                                                                                                            |
| Account Provider                    | org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider                                  |
| Account Mapper                      | org.forgerock.openam.authentication.modules.oidc.JwtAttributeMapper                                                |
| Attribute Mapper                    | Use default.                                                                                                       |
| Account Mapper Configuration        | Configure this to map sub to the attribute that contains your user’s BeyondIdentity Root Fingerprint               |
| Attribute Mapper Configuration      | Configure this to map sub to the attribute that contains your user’s BeyondIdentity Root Fingerprint               |
| Save Attributes in the session      | enabled                                                                                                            |
| OAuth 2.0 Mix-Up mitigation Enabled | disabled                                                                                                           |
| Token Issuer                        | https://auth.byndid.com/token                                                                                      |
| OpenID Connect Validation Type      | Well Known URL                                                                                                     |
| OpenID Connect Validation Value     | https://auth.byndid.com/.well-known/openid-configuration                                                           |
 
### Step 3: Test the integration

Open a new Incognito Mode Browser Window. 

Navigate to the tree where the Beyond Identity OIDC node is configured.

Login with Beyond Identity.

