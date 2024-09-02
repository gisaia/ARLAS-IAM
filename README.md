# ARLAS-IAM

ARLAS Identity and Access Management allows to manage organisations, users, roles, groups and permissions for ARLAS.

This project contains the back end, while [ARLAS-wui-iam](https://github.com/gisaia/ARLAS-wui-iam) is the front end.

This project is not aimed at being used alone. It belongs to the [ARLAS Exploration Stack](https://github.com/gisaia/ARLAS-Exploration-stack).

## Concepts:

ARLAS IAM manipulates the following concepts:
- `organisation`: ARLAS is multi-organisations: it partitions collections and users within organisations. A user can belong to multiple organisations. Similarly, a collection can be shared with multiple organisations. Only one organisation is the owner of the collection.
- `user`: a user account, linked to a unique email. A user can belong to multiple organisation. By default, a user has its own private organisation. User gain access to functions and data by belonging to organisations, groups and roles.
- `role`: an application role, within an organisation:
    - `user` for accessing ARLAS IAM
    - `dataset` for managing ARLAS collections
    - `owner` for managing the organisation
    - `builder`for building ARLAS dashboards
    - `tagger` for tagging hits from collections
    - `downloader` for accessing download functions from ARLAS AIAS
- `group`: set of permissions over collections and hits: allow to specify the visibility of collections and of their content
- `permission`: expression that delivers permissions.

ARLAS IAM also manages the user authentication with a login/password.

## License 

This project is licensed under the Apache License, Version 2.0 - see the LICENSE.txt file for details.
