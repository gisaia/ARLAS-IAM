package io.arlas.auth.core;

import io.arlas.auth.exceptions.*;
import io.arlas.auth.model.*;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AuthService {
    User login(String email, String password) throws NotFoundException;

    User createUser(String email) throws InvalidEmailException, AlreadyExistsException;
    Optional<User> readUser(UUID userId);
    User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException;
    Optional<User> deleteUser(UUID userId);
    Optional<User> activateUser(UUID userId);
    Optional<User> verifyUser(UUID userId, String password);
    Optional<User> deactivateUser(UUID userId);
    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

    Organisation createOrganisation(User owner, String name) throws AlreadyExistsException, ForbiddenOrganisationNameException;
    Optional<Organisation> deleteOrganisation(User user, UUID orgId);
    Set<Organisation> listOrganisations(User user);

    Organisation addUserToOrganisation(User owner, String email, UUID orgId) throws NotOwnerException, AlreadyExistsException, InvalidEmailException, NotFoundException;
    Organisation removeUserFromOrganisation(User owner, String removedUserId, UUID orgId) throws NotOwnerException;

    Role createRole(String name, UUID orgId, List<Permission> permissions);
    User addRoleToUser(String actingUserId, String targetUserId, String roleId);
    User removeRoleFromUser(String actingUserId, String targetUserId, String roleId);

    Group createGroup(String name, UUID orgId);
    User addUserToGroup(String actingUserId, String targetUserId, String groupId);
    User removeUserFromGroup(String actingUserId, String targetUserId, String groupId);
    Group addRoleToGroup(String actingUserId, String roleId, String groupId);
    Group removeRoleFromGroup(String actingUserId, String roleId, String groupId);

    List<Permission> listPermissions(String actingUserId, String targetUserId);
    Permission createPermission(String permission);
    User addPermissionToUser(UUID userId, String permissionId);
    User removePermissionFromUser(UUID userId, String permissionId);
}
