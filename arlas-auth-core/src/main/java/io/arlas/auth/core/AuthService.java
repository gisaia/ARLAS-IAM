package io.arlas.auth.core;

import io.arlas.auth.exceptions.AlreadyExistsException;
import io.arlas.auth.exceptions.InvalidEmailException;
import io.arlas.auth.exceptions.NonMatchingPasswordException;
import io.arlas.auth.exceptions.NotFoundException;
import io.arlas.auth.model.*;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface AuthService {
    User login(String email, String password) throws NotFoundException;

    User createUser(String email) throws InvalidEmailException, AlreadyExistsException;
    Optional<User> readUser(String userId);
    User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException;
    Optional<User> deleteUser(String userId);
    Optional<User> activateUser(String userId);
    Optional<User> verifyUser(String userId, String password);
    Optional<User> deactivateUser(String userId);
    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

    Organisation createOrganisation(User owner, String name) throws AlreadyExistsException;
    Optional<Organisation> deleteOrganisation(User user, String orgId);
    Set<Organisation> listOrganisations(User user);

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
