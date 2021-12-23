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

    Organisation createOrganisation(User owner) throws AlreadyExistsException, ForbiddenOrganisationNameException, NotOwnerException;
    Organisation deleteOrganisation(User user, UUID orgId) throws NotOwnerException;
    Set<Organisation> listOrganisations(User user);

    Organisation addUserToOrganisation(User owner, String email, UUID orgId) throws NotOwnerException, AlreadyExistsException, InvalidEmailException, NotFoundException;
    Organisation removeUserFromOrganisation(User owner, UUID removedUserId, UUID orgId) throws NotOwnerException, NotFoundException;

    Role createRole(String name, UUID orgId, Set<Permission> permissions) throws AlreadyExistsException, NotFoundException;
    User addRoleToUser(User owner, UUID orgId, UUID targetUserId, UUID roleId) throws NotFoundException, NotOwnerException;
    User removeRoleFromUser(User owner, UUID orgId, UUID targetUserId, UUID roleId) throws NotOwnerException, NotFoundException;

    Group createGroup(String name, UUID orgId);
    User addUserToGroup(User owner, UUID targetUserId, UUID groupId);
    User removeUserFromGroup(User owner, UUID targetUserId, UUID groupId);
    Group addRoleToGroup(User owner, UUID roleId, UUID groupId);
    Group removeRoleFromGroup(User owner, UUID roleId, UUID groupId);

    List<Permission> listPermissions(User owner, UUID targetUserId);
    Permission createPermission(String permission);
    User addPermissionToUser(UUID userId, UUID permissionId);
    User removePermissionFromUser(UUID userId, UUID permissionId);
}
