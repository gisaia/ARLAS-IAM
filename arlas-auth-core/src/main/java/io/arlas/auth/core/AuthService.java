package io.arlas.auth.core;

import io.arlas.auth.model.*;

import java.util.List;

public interface AuthService {
    User createUser(String email);
    User readUser(String userId);
    User updateUser(String userId, String oldPassword, String newPassword);
    User deleteUser(String userId);
    User activateUser(String userId);
    User deactivateUser(String userId);
    List<User> listUsers(String userId); // list users from the same organisations as the requesting user

    Organisation createOrganisation(User owner, String name);
    Organisation deleteOrganisation(String actingUserId, String orgId);
    List<Organisation> listOrganisations(String userId);
    User addUserToOrganisation(String actingUserId, String addedUserId, String orgId);
    User removeUserFromOrganisation(String actingUserId, String removedUserId, String orgId);

    Role createRole(String name, String orgId, List<Permission> permissions);
    User addRoleToUser(String actingUserId, String targetUserId, String roleId);
    User removeRoleFromUser(String actingUserId, String targetUserId, String roleId);

    Group createGroup(String name, String orgId);
    User addUserToGroup(String actingUserId, String targetUserId, String groupId);
    User removeUserFromGroup(String actingUserId, String targetUserId, String groupId);
    Group addRoleToGroup(String actingUserId, String roleId, String groupId);
    Group removeRoleFromGroup(String actingUserId, String roleId, String groupId);

    List<Permission> listPermissions(String actingUserId, String targetUserId);
    Permission createPermission(String permission);
    User addPermissionToUser(String userId, String permissionId);
    User removePermissionFromUser(String userId, String permissionId);
}
