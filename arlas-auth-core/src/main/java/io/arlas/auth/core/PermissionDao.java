package io.arlas.auth.core;

import io.arlas.auth.model.Permission;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface PermissionDao {

    Permission createPermission(Permission permission);

    Set<Permission> savePermissions(Set<Permission> permissions);

    Optional<Permission> readPermission(UUID permissionId);

    Optional<Permission> readPermission(String value);
}
