# Changelog

See [GitHub releases](https://github.com/jenkinsci/azure-ad-plugin/releases) for all newer versions.

## 1.2.3 (2021-02-20)
* Document update

## 1.2.2 (2020-12-23)
* Fix Azure AD matrix-based security cannot edit

## 1.2.1 (2020-10-26)
* Update maintainer

## 1.2.0 (2020-02-08)
* Enable setting callbackurl from request
* Fix some security vulnerability

## 1.1.2 (2020-01-07)
* Fix cache key missing issue

## 1.1.1 (2019-12-30)
* Add cache for information of authenticated users

## 1.1.0 (2019-11-08)
* Support group based authorization without 'Read directory data' permission
* Fix Slowness issue on initial authorization

## 1.0.0 (2019-05-30)
**This release includes breaking changes for Azure Identity platform, please follow up wiki to migrate.**
* Bump Jenkins version to 2.138.3
* Upgrade Microsoft identity platform from v1.0 to v2.0
* Add support for configuration as code
* Admin permission for tenant is no more necessary
* Jenkins server must enable HTTPS

## 0.3.3 (2019-04-11)
* Support named groups and users

## 0.3.2 (2019-01-18)
* Fix seed authentication issue

## 0.3.1 (2018-09-19)
* Upgrade Azure commons to 0.2.7
* Use UPN as Jenkins user id

## 0.3.0 (2018-02-09)
**Jenkins under version 2.60 is not supported any more!**
* Upgrade the dependency of matrix-auth to 2.2

## 0.2.0 (2018-01-18)
* Support project-based authorization
* Improve security

## 0.1.1 (2017-12-07)
* Fixed the CSRF protection issue.

## 0.1.0 (2017-12-01)
* Initial release
