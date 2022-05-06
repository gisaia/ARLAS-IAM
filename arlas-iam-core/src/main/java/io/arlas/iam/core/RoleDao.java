package io.arlas.iam.core;

import io.arlas.iam.model.Permission;
import io.arlas.iam.model.Role;
import io.arlas.iam.model.User;

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
