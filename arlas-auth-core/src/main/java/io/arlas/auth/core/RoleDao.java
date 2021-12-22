package io.arlas.auth.core;

import io.arlas.auth.model.Permission;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;

import java.util.List;

public interface RoleDao {

    Role createRole(String name, String orgId, List<Permission> permissions);

    User addRoleToUser(String actingUserId, String targetUserId, String roleId);

    User removeRoleFromUser(String actingUserId, String targetUserId, String roleId);

}
