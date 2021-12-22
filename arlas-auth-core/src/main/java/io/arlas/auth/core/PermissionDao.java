package io.arlas.auth.core;

import io.arlas.auth.model.Permission;

public interface PermissionDao {

    Permission createPermission(Permission permission);

}
