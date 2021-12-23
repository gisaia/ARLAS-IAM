package io.arlas.auth.core;

import io.arlas.auth.model.Permission;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface RoleDao {

    Role createRole(Role role, Set<Permission> permissions);

    Optional<Role> readRole(UUID roleId);

    Role addRoleToUser(User user, Role role);

    Role removeRoleFromUser(User user, Role role);

    Role addPermissionToRole(Permission permission, Role role);

    Role removePermissionFromRole(Permission permission, Role role);

}
