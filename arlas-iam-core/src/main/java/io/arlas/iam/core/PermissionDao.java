package io.arlas.iam.core;

import io.arlas.iam.model.Permission;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface PermissionDao {

    Permission createPermission(Permission permission);

    Set<Permission> savePermissions(Set<Permission> permissions);

    Optional<Permission> readPermission(UUID permissionId);

    Optional<Permission> readPermission(String value);
}