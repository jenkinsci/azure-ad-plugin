# Azure Active Directory Plugin
A Jenkins Plugin that supports authentication & authorization via Azure Active Directory.

## Setup In Azure Active Directory

Open `Azure Active Directory`, in `Properties`, copy Directory ID, it will be used as `tenant` in Jenkins

Register an application in AAD, copy the `Application ID`, it will be used as `Client ID`

In Application setting page, add a new entry [http://{your_jenkins_host}/securityRealm/finishLogin](http://{your-jenkins-domain}/securityRealm/finishLogin)

In Application setting page, click `Keys`, generate a new key, copy the `value`, it will be used as `Client Secret` in Jenkins.

In Application setting page, click `Required Permissions` and select `Windows Azure Service Management API`, then select `Access Azure Service Management as organization users (preview)` and save. This API and permission is for manage resource in subscription

In Application setting page, click `Required Permissions` and select `Windows Azure Active Directory`, then select `Read directory data` permissions in Application permissions section

Click `Grant Permissions`. If you are not an admin in your tenant, please contact admin to grant the permissions which declared as `require admin` in `Enable Access` page

Wait for the permissions taking effects.


## Setup In Jenkins

Click `Manage Jenkins` in the left menu, then click `Configure Global Security`, check `Enable security`


## Enable Azure Authentication

To enable Azure Authentication, check `Azure Active Directory` and fill in the credential.

Click `Verify Application` to make sure your input is valid.

## Enable Azure Authorization

To enable Azure Authentication, check `Azure Active Directory Matrix-based security`

