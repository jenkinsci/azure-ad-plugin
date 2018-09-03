# Azure Active Directory Plugin
A Jenkins Plugin that supports authentication & authorization via Azure Active Directory.

## Setup In Azure Active Directory

1. Open `Azure Active Directory`, in `Properties`, copy Directory ID, it will be used as `tenant` in Jenkins.

1. Register an application in AAD, copy the `Application ID`, it will be used as `Client ID`.

1. In Application setting page, add a new Reply URL `http://{your_jenkins_host}/securityRealm/finishLogin`. Make sure variable `jenkinsURL` set as `http://{your_jenkins_host}` for the file `jenkins.model.JenkinsLocationConfiguration.xml` in the `$JENKINS_HOME` folder.

1. In Application setting page, click `Keys`, generate a new key, copy the `value`, it will be used as `Client Secret` in Jenkins.

1. In Application setting page, click `Required Permissions` and select `Windows Azure Active Directory`, then select `Read directory data` permissions in Application permissions section

1. Click `Grant Permissions`. If you are not an admin in your tenant, please contact admin to grant the permissions which declared as `require admin` in `Enable Access` page. Wait for the permissions taking effects.


## Setup In Jenkins

Click `Manage Jenkins` in the left menu, then click `Configure Global Security`, check `Enable security`


## Enable Azure Authentication

To enable Azure Authentication, check `Azure Active Directory` and fill in the credential.

Click `Verify Application` to make sure your input is valid.

## Enable Azure Authorization

To enable Azure Authentication, check `Azure Active Directory Matrix-based security`

## FAQ
#### Q: How to recovery if Jenkins keeps failing during the login phase?
A: You can disable the security from the config file (see https://wiki.jenkins.io/display/JENKINS/Disable+security)

#### Q: Why getting a error "insufficient privileges to complete the operation" even having granted the permission?
A: It takes rather long time for the privileges to take effect, which could be 10-20 minutes. So just wait for a while and try again.
