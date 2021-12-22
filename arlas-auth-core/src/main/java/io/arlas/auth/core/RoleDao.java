package io.arlas.auth.core;

import io.arlas.auth.model.Permission;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;

import java.util.List;
import java.util.Set;

public interface RoleDao {

    Role createRole(Role role, Set<Permission> permissions);

    Role addRoleToUser(User user, Role role);

    Role removeRoleFromUser(User user, Role role);

}
