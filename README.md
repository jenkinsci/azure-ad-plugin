# Azure Active Directory Plugin
A Jenkins Plugin that supports authentication & authorization via Azure Active Directory.

## Setup In Azure Active Directory

1. Make sure your Jenkins server has enabled HTTPS. If your Jenkins instance is created by the [Jenkins Solution Template](https://docs.microsoft.com/en-us/azure/jenkins/install-jenkins-solution-template), you can update your NGINX config file at `/etc/nginx/sites-available/default`. More configuration details can be found [here](http://nginx.org/en/docs/http/configuring_https_servers.html).

1. Open `Azure Active Directory`, in `Properties`, copy Directory ID, it will be used as `tenant` in Jenkins.

1. Register an application in AAD, copy the `Application ID`, it will be used as `Client ID`.

1. In Application setting page, add a new Reply URL `https://{your_jenkins_host}/securityRealm/finishLogin`. Make sure variable `jenkinsURL` set as `https://{your_jenkins_host}` for the file `jenkins.model.JenkinsLocationConfiguration.xml` in the `$JENKINS_HOME` folder.

1. In Application setting page, click `Keys`, generate a new key, copy the `value`, it will be used as `Client Secret` in Jenkins.

1. To configure Azure Active Directory Matrix-based security, you have to add your `user/group` value with pattern `userName|groupName (principalName)`. The pattern `userName|groupName (objectId)` still works to make compatible with previous versions.

### Group Support

For group support you have two options:

1. Give Jenkins the right to `Read directory data` in `Azure Active Directory`(Azure admin right required), which in addition to group support also allows to use autocompletion when adding user/group in Azure Active Directory Matrix
1. Let Azure Active Directory provide the `groups` of an user as part of the id token.

**Option 1:**

Give Jenkins permission to `Read directory data` in `Azure Active Directory` to get autocompletion support in Azure Active Directory Matrix

1. In Application setting page, click `Required Permissions` and select `Windows Azure Active Directory`, then select `Read directory data` permissions in Application permissions section

1. Click `Grant Permissions`. If you are not an admin in your tenant, please contact admin to grant the permissions which declared as `require admin` in `Enable Access` page. Wait for the permissions taking effects.

**Option 2:**

Let Azure Active Directory provide the `groups` of an user as part of the id token.

1. In Azure Application settings, click `Authentication` and mark the `ID tokens` checkbox under `Advanced Settings -> Implicit grant`. Save settings.
1. In Azure Application settings, click `Manifest` and modify the `"groupMembershipClaims": "None"` value to `"groupMembershipClaims": "SecurityGroup"`. Save manifest.
1. To setup group based authentication in Jenkins, you should search and take note of the groups `Object Id` and `Name` you want to use for Jenkins authorization.
1. In Jenkins configure `Azure Active Directory Matrix`-based security and add the noted down groups one-by-one in the following notation: `groupName (objectId)`

## Setup In Jenkins

Click `Manage Jenkins` in the left menu, then click `Configure Global Security`, check `Enable security`


## Enable Azure Authentication

To enable Azure Authentication, check `Azure Active Directory` and fill in the credential.

Click `Verify Application` to make sure your input is valid.

## Enable Azure Authorization

To enable Azure Authentication, check `Azure Active Directory Matrix-based security`

## Version 1.0.0 Migration Instruction

In version 1.0.0, this plugin upgrades from Microsoft identity platform v1.0 to v2.0. Before you upgrade ad plugin to version 1.0.0, please read following items first.

1. Make sure your Jenkins server has enabled HTTPS. Microsoft identity platform v2.0 forces using HTTPS schema in reply uri for its applications. Please update the reply uri for your AAD application. You also need to update the url setting in `jenkins.model.JenkinsLocationConfiguration.xml` file and restart your Jenkins instance. If your Jenkins instance is created by the [Jenkins Solution Template](https://docs.microsoft.com/en-us/azure/jenkins/install-jenkins-solution-template), you can update your NGINX config file at `/etc/nginx/sites-available/default`. More configuration details can be found [here](http://nginx.org/en/docs/http/configuring_https_servers.html).

1. Go to your related AAD application, click `Manifest` to open the inline manifest editor. Replace the `optionalClaims` value as below. You can find more information about [this](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims#v20-optional-claims).

    ```json
        "optionalClaims": {
           "idToken": [
                 { 
                       "name": "family_name", 
                       "essential": false
                  },
                 { 
                       "name": "given_name", 
                       "essential": false
                  },
                               { 
                       "name": "upn", 
                       "essential": false
                  }
            ]
        },
    ```

## FAQ
#### Q: How to recovery if Jenkins keeps failing during the login phase?
A: You can disable the security from the config file (see https://wiki.jenkins.io/display/JENKINS/Disable+security)

#### Q: Why getting a error "insufficient privileges to complete the operation" even having granted the permission?
A: It takes rather long time for the privileges to take effect, which could be 10-20 minutes. So just wait for a while and try again.
