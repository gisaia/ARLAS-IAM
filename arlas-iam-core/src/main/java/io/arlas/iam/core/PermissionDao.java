package io.arlas.iam.core;

import io.arlas.iam.model.Permission;

public interface PermissionDao {

    Permission createOrUpdatePermission(Permission permission);
}
