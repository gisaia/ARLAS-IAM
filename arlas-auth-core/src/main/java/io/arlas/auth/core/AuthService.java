package io.arlas.auth.core;

import io.arlas.auth.exceptions.*;
import io.arlas.auth.model.*;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AuthService {
    User readUser(UUID userId, boolean checkActiveVerified) throws NotFoundException;

    User login(String email, String password) throws NotFoundException;

    User createUser(String email) throws InvalidEmailException, AlreadyExistsException;
    Optional<User> readUser(UUID userId);
    User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException;
    Optional<User> deleteUser(UUID userId);
    Optional<User> activateUser(UUID userId);
    Optional<User> verifyUser(UUID userId, String password);
    Optional<User> deactivateUser(UUID userId);
    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

    Organisation createOrganisation(User owner) throws AlreadyExistsException, NotOwnerException;
    Organisation deleteOrganisation(User owner, UUID orgId) throws NotOwnerException, NotFoundException;
    Set<Organisation> listOrganisations(User user);

    Organisation addUserToOrganisation(User owner, String email, UUID orgId) throws NotOwnerException, AlreadyExistsException, InvalidEmailException, NotFoundException;
    Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId) throws NotOwnerException, NotFoundException;

    Role createRole(User owner, String name, UUID orgId, Set<Permission> permissions) throws AlreadyExistsException, NotFoundException, NotOwnerException;
    User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotFoundException, NotOwnerException;
    User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotOwnerException, NotFoundException;

    Group createGroup(User owner, String name, UUID orgId) throws NotFoundException, AlreadyExistsException, NotOwnerException;
    User addUserToGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException;
    User removeUserFromGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException;
    Group addRoleToGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException;
    Group removeRoleFromGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException;

    Set<Permission> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException;
    Permission createPermission(String permission, boolean isSystem);
    User addPermissionToUser(UUID userId, UUID permissionId) throws NotFoundException;
    User removePermissionFromUser(UUID userId, UUID permissionId) throws NotFoundException;

    Role addPermissionToRole(UUID roleId, UUID permissionId) throws NotFoundException;
    Role removePermissionFromRole(UUID roleId, UUID permissionId) throws NotFoundException;
}
