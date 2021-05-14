# Beyond Identity

Beyond Identity provides the most secure authentication platform in the world. Breaking down barriers between cybersecurity, identity, and device management, Beyond Identity fundamentally changes the way the world logs in–eliminating passwords and providing users with a frictionless multi-factor login experience. Beyond passwordless, the company provides the zero-trust access needed to secure hybrid work environments, where tightly controlling which users and which devices are accessing critical cloud resources has become essential.

The advanced platform collects dozens of user and device risk signals during each login - enabling customers to enforce continuous, risk-based access control. The innovative architecture replaces passwords with the proven asymmetric cryptography that underpins TLS and protects trillions of dollars of transactions daily. Customers turn to Beyond Identity to stop cyberattacks, protect their most critical data, and meet compliance requirements


# Beyond Identity ForgeRock Integration Guide

This guide details the steps required to configure Beyond Identity as a passwordless authentication solution for 
your instance of ForgeRock Platform 7.
 
## Prerequisites
This integration relies on the ForgeRock Social Provider Handler Node which is available in ForgeRock Platform 7 and 
assumes integration between AM and IDM has been configured.

## Configuration

### Step 1: Setup Beyond Identity Admin Console Federation to ForgeRock AM

1. In the AM console, navigate to Realms > Realm Name > Applications > OAuth 2.0. 

2. Click Add Client, and then provide the Client ID, Client Secret, Redirection URI, and Scope. 

   Client ID: beyondidentityadmin

   Client Secret: specify_client_secret_here

   Redirection URIs: https://admin.byndid.com/auth/callback

   Scope(s): openid

3. Click Create to create the profile.

![BI Admin Console App](https://github.com/byndid/forgerock/blob/master/bi_admin_console_app.png)

4. Click on the newly created profile.

5. Click on the Advanced Tab

6. Turn on “Implied consent”

7. Click on “Save Changes”


### Step 2: Setup Beyond Identity Admin Console Access

1. Provide “Client ID” and “Client Secret” assigned to Admin Console Application in ForgeRock to Beyond Identity SE. Beyond Identity team will collect and populate those values using APIs.

2. After these values are provisioned, login and confirm that admin has access to Beyond Identity Admin Console.


### Step 3: Setup Beyond Identity User Console Federation to ForgeRock AM

1. In the AM console, navigate to Realms > Realm Name > Applications > OAuth 2.0. 

2. Click Add Client, and then provide the Client ID, Client Secret, Redirection URI, and Scope. 

   Client ID: beyondidentityuser

   Client Secret: specify_client_secret_here

   Redirection URIs: https://user.byndid.com/auth-user/callback

   Scope(s): openid

3. Click Create to create the profile.

![BI User Console App](https://github.com/byndid/forgerock/blob/master/bi_user_console_app.png)

4. Click on the newly created profile.

5. Click on the Advanced Tab

6. Turn on “Implied consent”

7. Click on “Save Changes”


### Step 4: Setup Beyond Identity User Console Authentication

1. Once logged into Beyond Identity Admin UI, click on Account Settings.

![BI Account Settings](https://github.com/byndid/forgerock/blob/master/bi_account_settings.png)

2. Click on “User Portal” tab and click on Edit.

3. Update SSO Issuer, SSO Client Id, and SSO Client Secret fields from the previous step.

![BI User Console Access](https://github.com/byndid/forgerock/blob/master/bi_user_console_access.png)


### Step 5: Setup Beyond Identity Access for User Console

1. Once logged into Beyond Identity Admin UI, click on “Integrations” tab and then click on OIDC Clients.

2. Click on “Add OIDC Client” and fill in Name, Redirect URI field and leave the default value for Token Signing Algorithm and Auth Method as shown below.

![BI Add OIDC Client](https://github.com/byndid/forgerock/blob/master/bi_add_oidc_client.png)

3. Click on the newly created OIDC Client configuration and write down Client ID and Client Secret Value. You will be using these values in the next step.

![BI Edit OIDC Client](https://github.com/byndid/forgerock/blob/master/bi_edit_oidc_client.png)


### Step 6: Configure Beyond Identity as an Identity Provider

#### Step 6a: Create Social Identity Provider Profile Transformation script

1. In the AM console, navigate to Realms > Realm Name > Scripts > New Script

   Name: Beyond Identity Profile Normalization

   Script Type: Select “Social Identity Provider Profile Transformation” from the dropdown.

2. Click on “Create”.

```javascript
import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object

import org.forgerock.json.JsonValue

JsonValue managedUser = json(object(
        field("userName", normalizedProfile.username)))

if (normalizedProfile.givenName.isNotNull()) managedUser.put("givenName", normalizedProfile.givenName)
if (normalizedProfile.familyName.isNotNull()) managedUser.put("sn", normalizedProfile.familyName)
if (normalizedProfile.email.isNotNull()) managedUser.put("mail", normalizedProfile.email)
if (normalizedProfile.userName.isNotNull()) managedUser.put("userName", normalizedProfile.userName)
if (normalizedProfile.postalAddress.isNotNull()) managedUser.put("postalAddress", normalizedProfile.postalAddress)
if (normalizedProfile.addressLocality.isNotNull()) managedUser.put("city", normalizedProfile.addressLocality)
if (normalizedProfile.addressRegion.isNotNull()) managedUser.put("stateProvince", normalizedProfile.addressRegion)
if (normalizedProfile.postalCode.isNotNull()) managedUser.put("postalCode", normalizedProfile.postalCode)
if (normalizedProfile.country.isNotNull()) managedUser.put("country", normalizedProfile.country)
if (normalizedProfile.phone.isNotNull()) managedUser.put("telephoneNumber", normalizedProfile.phone)

return managedUser
```

3. Click on “Save”.


#### Step 6b: Create Social Identity Provider Profile Transformation script

1. In the AM console, navigate to Realms > Realm Name > Scripts > New Script

   Name: BeyondIdentity_OpenIDConnect

   Script Type: Select “Social Identity Provider Profile Transformation” from the dropdown.

2. Click on “Create”.

```javascript
import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object

String[] nameArray = rawProfile.name.asString().split(" ");
String firstName = nameArray[0];
String lastName = nameArray[1];

return json(object(
        field("id", rawProfile.sub),
        field("email", rawProfile.email), 
        field("givenName", firstName), 
        field("familyName", lastName),
        field("username", rawProfile.sub)
))
```

3. Click on “Save”.


#### Step 6c: Configure Beyond Identity in the Social Identity Provider Service

1. In the AM console, navigate to Realms > Realm Name > Services > Social Identity Provider Service.

2. Click on “Secondary Configurations”.

3. Click on “Add a Secondary Configuration”.

4. Select “Client connection for providers that implement OpenID Connect Specification” from the dropdown then provide the following values:

   Name: BeyondIdentity
   
   Auth ID Key: sub
   
   Client ID: oidc_client_id_from_step_5.3
   
   Client Secret: oidc_client_secret_from_step_5.3
   
   Authentication Endpoint URL: https://auth.byndid.com/v2/authorize
   
   Access Token Endpoint URL: https://auth.byndid.com/v2/token
   
   User Profile Services URL: https://auth.byndid.com/v2/userinfo
   
   Redirect URI: enter_AM_URI_here
   
   Scope Delimiter: enter_a_space_character_here
   
   OAuth Scopes(s): openid
   
   Well Known Endpoint: https://auth.byndid.com/v2/.well-known/jwks.json

   UI Config Properties
   
   Key: buttonImage
   
   Value: https://byndid-public-assets.s3-us-west-2.amazonaws.com/logos/beyondidentity.png

5. Click “Add”

   Key: buttonDisplayName
   
   Value: Beyond Identity
   
   Transform Script: Select “BeyondIdentity_OpenIDConnect” from the dropdown.

![BI OIDC Config](https://github.com/byndid/forgerock/blob/master/bi_oidc_config.png)

6. Click “Create” to create the configuration.

7. Click “Save Changes” with default values.


#### Step 6d: Configure Beyond Identity Authentication Tree

1. In the AM console, navigate to Realms > Realm Name > Authentication > Trees.

2. Click on Create Tree

   Name: BeyondIdentity
   
   Now start buidling the tree as per the diagram shown below. This tree is made up of various nodes, which define actions taken during authentication. The nodes are a small unit of work which have a single purpose. You combine them together to define your unique user experience. 
   
   ![BI OIDC Auth Tree](https://github.com/byndid/forgerock/blob/master/bi_oidc_auth_tree.png)
   
   For most nodes, keep the default values, except as stated below:
   
| Node Name                           | Value                                                                                                               |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------- |
| Start                               |                                                                                                                     |
| Page Node                           |                                                                                                                     |
| Username Collector                  |                                                                                                                     |
| Password Collector                  |                                                                                                                     |
| Select Identity Provider            | Enable “Include local authentication”                                                                               |
| Social Provider Handler Node        | Transformation Script: Select “Beyond Identity Profile Normalization” from the dropdown                             |
| Identify Existing User              |                                                                                                                     |
| Data Store Decision                 |                                                                                                                     |
| Select Identity Provider            | Enable “Include local authentication” and “Offer only existing providers”                                           |
| Page Node                           |                                                                                                                     |
| Platfor Username                    |                                                                                                                     |
| Attribute Collector                 | Add “Attributes to collect”: sn, givenName, mail                                                                    |
| Platform Password                   |                                                                                                                     |
| Page Node                           |                                                                                                                     |
| Username Collector                  |                                                                                                                     |
| Password Collector                  |                                                                                                                     |
| Social Provider Handler Node        | Transformation Script: Select “Beyond Identity Profile Normalization” from the dropdown                             |
| Create Object                       |                                                                                                                     |
| Data Store Decision                 |                                                                                                                     |
| Patch Object                        |                                                                                                                     |
| Failure                             |                                                                                                                     |  
| Success                             |                                                                                                                     |

3. Click “Save”


### Step 7: Configure Beyond Identity as the OAuth2 Provider Service

This is used to set BeyondIdentity as the default tree for OIDC clients.

1. In the AM console, navigate to Realms > Realm Name > Services > OAuth2 Provider Service.

2. Click on “Advanced”.

3. Custom login URL Template:

```javascript
http://<your_am_domain>?service=BeyondIdentity&goto=${goto}<#if acrValues??>&acr_values=${acrValues}</#if><#if realm??>&realm=${realm}</#if><#if module??>&module=${module}</#if><#if service??>&service=${service}</#if><#if locale??>&locale=${locale}</#if>:
```

4. Click on “Save Changes”.


## Setting up Test Users

### User Enrollment

1. To enroll (provision) a user in the Beyond Identity experience:

   Use a SCIM Connector and provision users from ForgeRock to Beyond Identity.

   To configure SCIM Connector in ForgeRock refer to: https://backstage.forgerock.com/docs/idm/7/connector-reference/chap-scim.html
   
   SCIM API Endpoints:
   
   https://api.byndid.com/scim/v2/Users

   https://api.byndid.com/scim/v2/Groups


2. Enrolled user will receive an email from Beyond Identity welcoming them to the new Identity Provider.

   See image below for reference:

![BI Enrollment Email](https://github.com/byndid/forgerock/blob/master/bi_enrollment_email.png)

3. Each enrolled user will be asked to follow the two steps below:

   Step 1: Download the Beyond Identity Authenticator to their device.

   When the user clicks “View Download Options”, the Beyond Identity Authenticator downloads page will open in a browser with all supported platforms displayed. 
   
   The user should download and install the Beyond Identity Authenticator on their device if they have not already.

   Now that the user has the Authenticator installed on their device, they should proceed to Step 2 as there is not yet a user credential associated with the   Authenticator on that device.

   Step 2: Register their Credential in the Beyond Identity IdP.

   By clicking on Step 2 “Register New Credential”, the user’s credential will get enrolled in the Beyond Identity service on the back end. On the front end, users who click Step 2 will be taken to the Beyond Identity Authenticator where they will see the progress of their credential registration. Once completed, the user will see a credentials in the Authenticator. 
   
   See example image below:

![BI Authenticator](https://github.com/byndid/forgerock/blob/master/bi_authenticator.png)

## User Authentication (Signing in)

1. Each enrolled user can visit their ForgeRock instance or any application supported by your SSO to sign into their corporate applications. 

2. The ForgeRock application or SSO-supported application will display a link to sign in using Beyond Identity.

3. The user should click on the link to be signed into their application, without the use of a password. The Beyond Identity app along with a success notification will display.

   Note: For iOS devices, some application sign-in processes will ask the user to exit out of the Beyond Identity Authenticator to return to their app after successful authentication.

## User Deprovisioning

To deprovision the users, use the same SCIM Connector described above.

