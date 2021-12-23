package io.arlas.auth.core;

import io.arlas.auth.model.Permission;

import java.util.Optional;
import java.util.UUID;

public interface PermissionDao {

    Permission createPermission(Permission permission);

    Optional<Permission> readPermission(UUID permissionId);

}
