# Azure Active Directory Plugin

> ***Important***: This plug-in is maintained by the Jenkins community and won’t be supported by Microsoft as of February 29, 2024.

A Jenkins Plugin that supports authentication & authorization via Azure Active Directory.

## Setup In Azure Active Directory

1. Open `Azure Active Directory`, click `App registrations`

1. Click `New registration`

1. Add a new Reply URL `https://{your_jenkins_host}/securityRealm/finishLogin`. Make sure "Jenkins URL" (Manage Jenkins => Configure System) is set to the same value as `https://{your_jenkins_host}`.

1. Click `Certificates & secrets`, under Client secrets click `New client secret` to generate a new key, copy the `value`, it will be used as `Client Secret` in Jenkins.

1. Click `Authentication`, under 'Implicit grant and hybrid flows', enable `ID tokens`.

1. (optional) To enable AzureAD group support: Click `Manifest` and modify the `"groupMembershipClaims": null` value to `"groupMembershipClaims": "SecurityGroup"`, then 'Save' it.

### Setup Azure AD permissions (optional, but recommended)

In order for Jenkins to be able to lookup data from Azure AD it needs some Graph API permissions.

This is used for:

* Autocompleting users and groups on the 'Security' page
* Jenkins looking up the user, e.g. when you use the Rest API
* Group display name support (rather than just object ID)

_Note: You can skip this part and just use the claims returned when authenticating._

1. Click `API permissions`

1. Add a permission

1. Microsoft Graph

1. Application permissions

1. Add 'User.Read.All', 'Group.Read.All' and 'People.Read.All'

1. Click `Grant admin consent`. If you are not an admin in your tenant, please contact an admin to grant the permissions.

## Setup In Jenkins

Click `Manage Jenkins` in the left menu, then click `Security`

## Authentication

1. Check `Azure Active Directory` and fill in the credential.

1. Click `Verify Application` to make sure your input is valid.

1. Save the configuration, (logged-in users will have permission to do anything)

1. Log in with Azure AD

1. Return to 'Security' to configure authorization

_Note: if you haven't setup Graph API permissions, verify application will fail, skip over this step_

## Authorization

Jenkins will match permissions based on the Object ID of a user or group.

This plugin extends the traditional [Matrix Authorization Strategy](https://plugins.jenkins.io/matrix-auth/)
with the ability to search by users / groups by display name when configuring the authorization rules.

To use this feature:

1. Click `Azure Active Directory Matrix-based security`
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
* User principal name (Rest API authentication only)

## FAQ
#### Q: How to recover if Jenkins keeps failing during the login phase?
A: You can disable the security from the config file (see [https://www.jenkins.io/doc/book/security/access-control/disable/](https://www.jenkins.io/doc/book/security/access-control/disable/))

#### Q: Why am I getting an error "insufficient privileges to complete the operation" even after having granted the permission?

A: It can take a long time for the privileges to take effect, which could be 10-20 minutes. Just wait for a while and try again.
