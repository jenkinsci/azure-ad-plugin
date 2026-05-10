# Microsoft Entra ID Plugin (previously Azure Active Directory Plugin)

> ***Important***: This plug-in is maintained by the Jenkins community and won’t be supported by Microsoft as of February 29, 2024.

A Jenkins Plugin that supports authentication & authorization via Microsoft Entra ID ([previously known as Azure Active Directory](https://learn.microsoft.com/entra/fundamentals/new-name)).

## Setup In Microsoft Entra ID

1. Open `Microsoft Entra ID`, click `App registrations`

1. Click `New registration`

1. Add a new Reply URL `https://{your_jenkins_host}/securityRealm/finishLogin`. Make sure "Jenkins URL" (Manage Jenkins => Configure System) is set to the same value as `https://{your_jenkins_host}`.

1. Click `Certificates & secrets`

   - To use a client secret: Under Client secrets, click `New client secret` to generate a new key. Copy the `value`, it will be used as `Client Secret` in Jenkins.

   - To use a certificate: Under Certificates, click `Upload certificate` to upload your certificate. This certificate will be used for client certificate authentication in Jenkins. You will need to use the corresponding private key associated with this certificate in PEM format.

1. Click `Authentication`, under 'Implicit grant and hybrid flows', enable `ID tokens`.

1. (optional) To enable Microsoft Entra ID group support: Click `Manifest` and modify the `"groupMembershipClaims": null` value to `"groupMembershipClaims": "SecurityGroup"`, then 'Save' it.

### Setup Microsoft Entra ID permissions (optional, but recommended)

In order for Jenkins to be able to lookup data from Microsoft Entra ID it needs some Graph API permissions.

This is used for:

* Autocompleting users and groups on the 'Security' page
* Jenkins looking up the user, e.g. when you use the Rest API
* Group display name support (rather than just object ID)

_Note: You can skip this part and just use the claims returned when authenticating._

1. Click `API permissions`

1. Add a permission

1. Microsoft Graph

1. Application permissions

1. Add 'User.ReadBasic.All', 'GroupMember.Read.All'

1. Click `Grant admin consent`. If you are not an admin in your tenant, please contact an admin to grant the permissions.

## Setup In Jenkins

Click the settings icon in the header, then click `Security`

## Authentication

1. For the Security Realm select `Entra ID` and fill in the credential.

1. Click `Verify Application` to make sure your input is valid.

1. Save the configuration, (logged-in users will have permission to do anything)

1. Log in with Microsoft Entra ID

1. Return to 'Security' to configure authorization

_Note: if you haven't setup Graph API permissions, verify application will fail, skip over this step_

## Authorization

Jenkins will match permissions based on the Object ID of a user or group.

This plugin extends the traditional [Matrix Authorization Strategy](https://plugins.jenkins.io/matrix-auth/)
with the ability to search by users / groups by display name when configuring the authorization rules.

To use this feature:

1. Click `Entra ID Matrix-based security`
1. Search for user in 'Azure User/group to add' and click Add
1. Select the permission(s) in the table
1. Click 'Apply'

You can still use other authorization strategies such as:

* [Matrix Authorization Strategy](https://plugins.jenkins.io/matrix-auth/)
* [Folder-based Authorization Strategy](https://plugins.jenkins.io/folder-auth/)
* [Role-based Authorization Strategy](https://plugins.jenkins.io/role-strategy/)

The following can normally be used:

* Object ID of user or group
* Display name of group (Only if Graph API permissions granted)
* `preferred_username` claim which is normally the 'User principal name', but not always.

It is recommended that you use the Object ID, after adding the object ID you will be
able to see the user or group's display name.

## Configuration as Code and Job DSL support
The plugin has full support for use in Configuration as Code and Job DSL.

For an example combining the two, see the [configuration-as-code.yml](./src/test/resources/com/microsoft/jenkins/azuread/integrations/casc/configuration-as-code.yml) test resource.

## Using Workload Identity (Federated Credentials)

You can use **Workload Identity** to authenticate with Entra ID without storing a client secret or certificate. Instead, Jenkins uses a JWT token issued by an OIDC identity provider (e.g. a Kubernetes cluster, GitHub Actions, or a custom OIDC provider) that is exchanged for an Entra ID access token via federated credentials.

### Prerequisites

1. **OIDC Identity Provider** — any provider that issues JWT tokens with a publicly accessible discovery document (`.well-known/openid-configuration`) and JWKS endpoint. Examples include:
   - Kubernetes clusters with OIDC Issuer enabled
   - GitHub Actions
   - A custom OIDC provider (e.g. keys and metadata hosted on a storage account)

2. **Entra ID App Registration** — the same one used for user login. On the App Registration:
   - Go to **Certificates & secrets** → **Federated credentials** → **Add credential**
   - Configure the **Issuer**, **Subject**, and **Audience** to match the tokens issued by your OIDC provider
   - Save the credential

3. **Federated Token File** — a file containing a valid JWT issued by your OIDC provider. Set the `AZURE_FEDERATED_TOKEN_FILE` environment variable to the path of this file.

### Configuring via Jenkins UI

1. Go to **Manage Jenkins** → **Security**
2. Under Security Realm, select **Entra ID**
3. Enter the **Client ID** and **Tenant**
4. Under **Authentication Type**, select **Workload Identity (Federated Credentials)**
5. Click **Save**

### Configuring via JCasC

```yaml
jenkins:
  securityRealm:
    azure:
      clientid: "<YOUR_APP_CLIENT_ID>"
      credentialtype: "WorkloadIdentity"
      tenant: "<YOUR_TENANT_ID>"
      cacheduration: 3600
      fromrequest: true
```

### Troubleshooting

- If you see `AZURE_FEDERATED_TOKEN_FILE environment variable is not set`, ensure the environment variable points to a valid JWT token file.
- Verify the Federated Identity Credential on the App Registration has the correct **Issuer**, **Subject**, and **Audience** values matching your OIDC provider's tokens. Decode the token (`cat $AZURE_FEDERATED_TOKEN_FILE | cut -d. -f2 | base64 -d`) to inspect the `iss`, `sub`, and `aud` claims.
- A `400` error from the token endpoint typically means a mismatch between the token claims and the federated credential configuration.

## FAQ

### Q: How to recover if Jenkins keeps failing during the login phase?
A: You can disable the security from the config file (see [https://www.jenkins.io/doc/book/security/access-control/disable/](https://www.jenkins.io/doc/book/security/access-control/disable/))

### Q: Why am I getting an error "insufficient privileges to complete the operation" even after having granted the permission?

A: It can take a long time for the privileges to take effect, which could be 10-20 minutes. Just wait for a while and try again.
