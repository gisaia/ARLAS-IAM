package io.arlas.ums.core;

import io.arlas.ums.model.Permission;
import io.arlas.ums.model.Role;
import io.arlas.ums.model.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleDao {

    Role createRole(Role role);

    Optional<Role> readRole(UUID roleId);

    Role addRoleToUser(User user, Role role);

    Role removeRoleFromUser(User user, Role role);

    Role addPermissionToRole(Permission permission, Role role);

    Role removePermissionFromRole(Permission permission, Role role);

    List<Role> getSystemRoles();
}
