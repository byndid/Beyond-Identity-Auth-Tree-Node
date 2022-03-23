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
   
   Well Known Endpoint: https://auth.byndid.com/v2/.well-known/openid-configuration

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
   
   Now start building the tree as per the diagram shown below. This tree is made up of various nodes, which define actions taken during authentication. The nodes are a small unit of work which have a single purpose. You combine them together to define your unique user experience.
   
   ![BI OIDC Auth Tree](https://github.com/byndid/forgerock/blob/master/bi_oidc_auth_tree.png)
 
    First add the nodes as per the list below. Note that some nodes are encased in other nodes. For most nodes, keep the default values, except where mentioned. Then connect the nodes as per the diagram above and complete the tree.

   
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
| Platform Username                   |                                                                                                                     |
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
http://<your_am_domain>?service=BeyondIdentity&goto=${goto}<#if acrValues??>&acr_values=${acrValues}</#if><#if realm??>&realm=${realm}</#if><#if module??>&module=${module}</#if><#if service??>&service=${service}</#if><#if locale??>&locale=${locale}</#if>
```

4. Click on “Save Changes”.

### Configure ForgeRock and Beyond Identity for AM 7.1 changes

1. Navigate to Service -> OAuth 2 provider -> Advanced OpenID Connect and enable the following configurations.
   * Enable `claims_parameter_supported`
   * Enable `Always Return Claims in ID Tokens`

2. Add `sub` to `profile` array in scopeClaimsMap in OIDC claims script. To do this, navigate to scripts, and replace the `OIDC-Claims-Script` with this.
```
/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
import com.iplanet.sso.SSOException
import com.sun.identity.idm.IdRepoException
import org.forgerock.oauth2.core.exceptions.InvalidRequestException
import org.forgerock.oauth2.core.UserInfoClaims
import org.forgerock.openidconnect.Claim

/*
* Defined variables:
* logger - always presents, the "OAuth2Provider" debug logger instance
* claims - always present, default server provided claims - Map<String, Object>
* claimObjects - always present, default server provided claims - List<Claim>
* session - present if the request contains the session cookie, the user's session object
* identity - always present, the identity of the resource owner
* scopes - always present, the requested scopes
* scriptName - always present, the display name of the script
* requestProperties - always present, contains a map of request properties:
*                     requestUri - the request URI
*                     realm - the realm that the request relates to
*                     requestParams - a map of the request params and/or posted data. Each value is a list of one or
*                     more properties. Please note that these should be handled in accordance with OWASP best practices.
* clientProperties - present if the client specified in the request was identified, contains a map of client
*                    properties:
*                    clientId - the client's Uri for the request locale
*                    allowedGrantTypes - list of the allowed grant types (org.forgerock.oauth2.core.GrantType)
*                                        for the client
*                    allowedResponseTypes - list of the allowed response types for the client
*                    allowedScopes - list of the allowed scopes for the client
*                    customProperties - A map of the custom properties of the client.
*                                       Lists or maps will be included as sub-maps, e.g:
*                                       testMap[Key1]=Value1 will be returned as testmap -> Key1 -> Value1
* requestedClaims - Map<String, Set<String>>
*                  always present, not empty if the request contains a claims parameter and server has enabled
*                  claims_parameter_supported, map of requested claims to possible values, otherwise empty,
*                  requested claims with no requested values will have a key but no value in the map. A key with
*                  a single value in its Set indicates this is the only value that should be returned.
* requestedTypedClaims - List<Claim>
*                       always present, not empty if the request contains a claims parameter and server has enabled
*                       claims_parameter_supported, list of requested claims with claim name, requested possible values
*                       and if claim is essential, otherwise empty,
*                       requested claims with no requested values will have a claim with no values. A claims with
*                       a single value indicates this is the only value that should be returned.
* claimsLocales - the values from the 'claims_locales' parameter - List<String>
* Required to return a Map of claims to be added to the id_token claims
*
* Expected return value structure:
* UserInfoClaims {
*    Map<String, Object> values; // The values of the claims for the user information
*    Map<String, List<String>> compositeScopes; // Mapping of scope name to a list of claim names.
* }
*/

// user session not guaranteed to be present
boolean sessionPresent = session != null

/*
 * Pulls first value from users profile attribute
 *
 * @param claim The claim object.
 * @param attr The profile attribute name.
 */
def fromSet = { claim, attr ->
    if (attr != null && attr.size() == 1){
        attr.iterator().next()
    } else if (attr != null && attr.size() > 1){
        attr
    } else if (logger.warningEnabled()) {
        logger.warning("OpenAMScopeValidator.getUserInfo(): Got an empty result for claim=$claim");
    }
}

// ---vvvvvvvvvv--- EXAMPLE CLAIM ATTRIBUTE RESOLVER FUNCTIONS ---vvvvvvvvvv---
/*
 * Claim resolver which resolves the value of the claim from its requested values.
 *
 * This resolver will return a value if the claim has one requested values, otherwise an exception is thrown.
 */
defaultClaimResolver = { claim ->
    if (claim.getValues().size() == 1) {
        [(claim.getName()): claim.getValues().iterator().next()]
    } else {
        [:]
    }
}

/*
 * Claim resolver which resolves the value of the claim by looking up the user's profile.
 *
 * This resolver will return a value for the claim if:
 * # the user's profile attribute is not null
 * # AND the claim contains no requested values
 * # OR the claim contains requested values and the value from the user's profile is in the list of values
 *
 * If no match is found an exception is thrown.
 */
userProfileClaimResolver = { attribute, claim, identity ->
    if (identity != null) {
        userProfileValue = fromSet(claim.getName(), identity.getAttribute(attribute))
        if (userProfileValue != null && (claim.getValues() == null || claim.getValues().isEmpty() || claim.getValues().contains(userProfileValue))) {
            return [(claim.getName()): userProfileValue]
        }
    }
    [:]
}

/*
 * Claim resolver which resolves the value of the claim of the user's address.
 *
 * This resolver will return a value for the claim if:
 * # the value of the address is not null
 *
 */
userAddressClaimResolver = { claim, identity ->
    if (identity != null) {
        addressFormattedValue = fromSet(claim.getName(), identity.getAttribute("postaladdress"))
        if (addressFormattedValue != null) {
            return [
                    "formatted" : addressFormattedValue
            ]
        }
    }
    [:]
}

/*
 * Claim resolver which resolves the value of the claim by looking up the user's profile.
 *
 * This resolver will return a value for the claim if:
 * # the user's profile attribute is not null
 * # AND the claim contains no requested values
 * # OR the claim contains requested values and the value from the user's profile is in the list of values
 *
 * If the claim is essential and no value is found an InvalidRequestException will be thrown and returned to the user.
 * If no match is found an exception is thrown.
 */
essentialClaimResolver = { attribute, claim, identity ->
    if (identity != null) {
        userProfileValue = fromSet(claim.getName(), identity.getAttribute(attribute))
        if (claim.isEssential() && (userProfileValue == null || userProfileValue.isEmpty())) {
            throw new InvalidRequestException("Could not provide value for essential claim $claim")
        }
        if (userProfileValue != null && (claim.getValues() == null || claim.getValues().isEmpty() || claim.getValues().contains(userProfileValue))) {
            return [(claim.getName()): userProfileValue]
        }
    }
    return [:]
}

/*
 * Claim resolver which expects the user's profile attribute value to be in the following format:
 * "language_tag|value_for_language,...".
 *
 * This resolver will take the list of requested languages from the 'claims_locales' authorize request
 * parameter and attempt to match it to a value from the users' profile attribute.
 * If no match is found an exception is thrown.
 */
claimLocalesClaimResolver = { attribute, claim, identity ->
    if (identity != null) {
        userProfileValue = fromSet(claim.getName(), identity.getAttribute(attribute))
        if (userProfileValue != null) {
            localeValues = parseLocaleAwareString(userProfileValue)
            locale = claimsLocales.find { locale -> localeValues.containsKey(locale) }
            if (locale != null) {
                return [(claim.getName()): localeValues.get(locale)]
            }
        }
    }
    return [:]
}

/*
 * Claim resolver which expects the user's profile attribute value to be in the following format:
 * "language_tag|value_for_language,...".
 *
 * This resolver will take the language tag specified in the claim object and attempt to match it to a value
 * from the users' profile attribute. If no match is found an exception is thrown.
 */
languageTagClaimResolver = { attribute, claim, identity ->
    if (identity != null) {
        userProfileValue = fromSet(claim.getName(), identity.getAttribute(attribute))
        if (userProfileValue != null) {
            localeValues = parseLocaleAwareString(userProfileValue)
            if (claim.getLocale() != null) {
                if (localeValues.containsKey(claim.getLocale())) {
                    return [(claim.getName()): localeValues.get(claim.getLocale())]
                } else {
                    entry = localeValues.entrySet().iterator().next()
                    return [(claim.getName() + "#" + entry.getKey()): entry.getValue()]
                }
            } else {
                entry = localeValues.entrySet().iterator().next()
                return [(claim.getName()): entry.getValue()]
            }
        }
    }
    return [:]
}

/*
 * Given a string "en|English,jp|Japenese,fr_CA|French Canadian" will return map of locale -> value.
 */
parseLocaleAwareString = { s ->
    return result = s.split(",").collectEntries { entry ->
        split = entry.split("\\|")
        [(split[0]): value = split[1]]
    }
}
// ---^^^^^^^^^^--- EXAMPLE CLAIM ATTRIBUTE RESOLVER FUNCTIONS ---^^^^^^^^^^---

// -------------- UPDATE THIS TO CHANGE CLAIM TO ATTRIBUTE MAPPING FUNCTIONS ---------------
/*
 * List of claim resolver mappings.
 */
// [ {claim}: {attribute retriever}, ... ]
claimAttributes = [
        "email": userProfileClaimResolver.curry("mail"),
        "address": { claim, identity -> [ "address" : userAddressClaimResolver(claim, identity) ] },
        "phone_number": userProfileClaimResolver.curry("telephonenumber"),
        "given_name": userProfileClaimResolver.curry("givenname"),
        "zoneinfo": userProfileClaimResolver.curry("preferredtimezone"),
        "family_name": userProfileClaimResolver.curry("sn"),
        "locale": userProfileClaimResolver.curry("preferredlocale"),
        "name": userProfileClaimResolver.curry("cn")
]


// -------------- UPDATE THIS TO CHANGE SCOPE TO CLAIM MAPPINGS --------------
/*
 * Map of scopes to claim objects.
 */
// {scope}: [ {claim}, ... ]
scopeClaimsMap = [
        "email": [ "email" ],
        "address": [ "address" ],
        "phone": [ "phone_number" ],
        "profile": [ "given_name", "zoneinfo", "family_name", "locale", "name", "sub" ]
]


// ---------------- UPDATE BELOW FOR ADVANCED USAGES -------------------
if (logger.messageEnabled()) {
    scopes.findAll { s -> !("openid".equals(s) || scopeClaimsMap.containsKey(s)) }.each { s ->
        logger.message("OpenAMScopeValidator.getUserInfo()::Message: scope not bound to claims: $s")
    }
}

/*
 * Computes the claims return key and value. The key may be a different value if the claim value is not in
 * the requested language.
 */
def computeClaim = { claim ->
    try {
        claimResolver = claimAttributes.get(claim.getName(), { claimObj, identity -> defaultClaimResolver(claim)})
        claimResolver(claim, identity)
    } catch (IdRepoException e) {
        if (logger.warningEnabled()) {
            logger.warning("OpenAMScopeValidator.getUserInfo(): Unable to retrieve attribute=$attribute", e);
        }
    } catch (SSOException e) {
        if (logger.warningEnabled()) {
            logger.warning("OpenAMScopeValidator.getUserInfo(): Unable to retrieve attribute=$attribute", e);
        }
    }
}

/*
 * Converts requested scopes into claim objects based on the scope mappings in scopeClaimsMap.
 */
def convertScopeToClaims = {
    scopes.findAll { scope -> "openid" != scope && scopeClaimsMap.containsKey(scope) }.collectMany { scope ->
        scopeClaimsMap.get(scope).collect { claim ->
            new Claim(claim)
        }
    }
}

// Creates a full list of claims to resolve from requested scopes, claims provided by AS and requested claims
def claimsToResolve = convertScopeToClaims() + claimObjects + requestedTypedClaims

// Computes the claim return key and values for all requested claims
computedClaims = claimsToResolve.collectEntries() { claim ->
    result = computeClaim(claim)
}

// Computes composite scopes
def compositeScopes = scopeClaimsMap.findAll { scope ->
    scopes.contains(scope.key)
}

return new UserInfoClaims((Map)computedClaims, (Map)compositeScopes)
```

3. Set `Token Field` to `subname` in the Beyond Identity SSO settings for both the admin console and user console.

4. In Beyond Identity Admin Console, set `Token Field Lookup` to `externalId`

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

