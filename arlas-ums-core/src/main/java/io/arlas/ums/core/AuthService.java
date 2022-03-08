package io.arlas.ums.core;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.ums.exceptions.*;
import io.arlas.ums.model.*;

import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AuthService {
    User readUser(UUID userId, boolean checkActiveVerified) throws NotFoundException;

    LoginSession login(String email, String password, String issuer) throws ArlasException;
    DecodedJWT verifyToken(String token);
    void logout(UUID userId);
    LoginSession refresh(User user, String refreshToken, String issuer) throws ArlasException;
    String createPermissionToken(String subject, String issuer, Date iat) throws ArlasException;

    User createUser(String email, String locale, String timezone) throws InvalidEmailException, AlreadyExistsException, SendEmailException;
    Optional<User> readUser(UUID userId);
    User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException;
    void deleteUser(UUID userId);
    Optional<User> activateUser(UUID userId);
    Optional<User> verifyUser(UUID userId, String verifyToken, String password) throws AlreadyVerifiedException, NonMatchingPasswordException;

    Optional<User> deactivateUser(UUID userId);
    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

    Organisation createOrganisation(User owner) throws AlreadyExistsException, NotOwnerException;
    void deleteOrganisation(User owner, UUID orgId) throws NotOwnerException, NotFoundException;
    Set<Organisation> listOrganisations(User user);

    Organisation addUserToOrganisation(User owner, String email, UUID orgId) throws NotOwnerException, NotFoundException;
    Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId) throws NotOwnerException, NotFoundException;

    Role createRole(User owner, String name, UUID orgId, Set<Permission> permissions) throws AlreadyExistsException, NotFoundException, NotOwnerException;
    User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotFoundException, NotOwnerException;
    User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotOwnerException, NotFoundException;

    Group createGroup(User owner, String name, UUID orgId) throws NotFoundException, AlreadyExistsException, NotOwnerException;
    User addUserToGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException;
    Group removeUserFromGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException;
    Group addRoleToGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException;
    Group removeRoleFromGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException;

    Set<String> listPermissions(UUID userId) throws NotFoundException;
    Set<String> listPermissions(UUID userId, UUID orgId) throws NotOwnerException, NotFoundException;
    Set<String> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException;
    Permission createPermission(String permission, boolean isSystem);
    User addPermissionToUser(UUID userId, UUID permissionId) throws NotFoundException;
    User removePermissionFromUser(UUID userId, UUID permissionId) throws NotFoundException;

    Role addPermissionToRole(UUID roleId, UUID permissionId) throws NotFoundException;
    Role removePermissionFromRole(UUID roleId, UUID permissionId) throws NotFoundException;
}