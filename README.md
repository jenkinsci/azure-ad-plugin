# azure-oauth-plugin
A Jenkins Plugin that supports authentication via Azure OAuth



# Setup In Azure Active Directory

Open `Azure Active Directory`, in `Properties`, copy Directory ID, it will be used as `tenant` in Jenkins

Register an application in AAD, copy the `Application ID`, it will be used as `Client ID`

In Application setting page, add a new entry [http://{your-jenkins-domain}/securityRealm/finishLogin](http://{your-jenkins-domain}/securityRealm/finishLogin)

In Application setting page, click `Keys`, generate a new key, copy the `value`, it will be used as `Client Secret` in Jenkins.

In Application setting page, click `Required Permissions` and select `Windows Azure Service Management API`, then select `Access Azure Service Management as organization users (preview)` and save. This API and permission is for manage resource in subscription

In Application setting page, click `Required Permissions` and select `Microsoft Graph`, then select `Read all groups` and `Read directory data` permissions in Application permissions section

Click `Grant Permissions`. If you are not an admin in your tenant, please contact admin to grant the permissions which declared as `require admin` in `Enable Access` page

Wait at most 20 minutes to let the permissions take effects.


# Setup In Jenkins

Click `Manage Jenkins` in the left menu, then click `Configure Global Security`, check `Enable security`


## Enable Azure Authentication

To enable Azure Authentication, check `Azure OAuth Plugin` and fill in the textbox copied from Azure portal.

Click `Verify Application` to make sure your input is valid.

## Enable Azure Aurhorization

To enable Azure Authentication, check `Azure Active Directory Role-Based Strategy`

Click `Save`, click `Manage Jenkins` and then `Manage and Assign Roles` to manage roles and assign roles to Azure users or groups.

## Assign Roles
If you are going to make roles for Azure users or groups, the format for `User/group to add` is `Display Name(Object ID)`. You can wait for auto-completion of textbox and select one of them to make sure your input is valid. 
