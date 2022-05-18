package io.arlas.iam.core;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.model.*;

import java.util.*;

public interface AuthService {
    void initDatabase();
    User readUser(UUID userId, boolean checkActiveVerified) throws NotFoundException;

    LoginSession login(String email, String password, String issuer) throws ArlasException;
    DecodedJWT verifyToken(String token);
    void logout(UUID userId);
    LoginSession refresh(User user, String refreshToken, String issuer) throws ArlasException;
    String createPermissionToken(String subject, String issuer, Date iat) throws ArlasException;

    User createUser(String email, String locale, String timezone) throws InvalidEmailException, AlreadyExistsException, SendEmailException;
    User verifyUser(UUID userId, String verifyToken, String password) throws AlreadyVerifiedException, NonMatchingPasswordException, ExpiredTokenException, SendEmailException, NotFoundException;

    Optional<User> readUser(UUID userId);
    User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException;
    void deleteUser(UUID userId) throws NotAllowedException;

    Optional<User> activateUser(UUID userId);
    Optional<User> deactivateUser(UUID userId) throws NotAllowedException;

    Organisation createOrganisation(User user, String name) throws AlreadyExistsException, NotOwnerException, NotFoundException;
    Organisation createOrganisation(User owner) throws AlreadyExistsException, NotOwnerException, NotFoundException;
    void deleteOrganisation(User owner, UUID orgId) throws NotOwnerException, NotFoundException;
    Set<Organisation> listOrganisations(User user);

    Set<OrganisationMember> listOrganisationUsers(User user, UUID orgId) throws NotOwnerException, NotFoundException;
    Organisation addUserToOrganisation(User owner, String email, UUID orgId, Boolean isOwner) throws NotOwnerException, NotFoundException, AlreadyExistsException;
    Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId) throws NotOwnerException, NotFoundException, NotAllowedException;

    Role createRole(User owner, String name, String description, UUID orgId) throws AlreadyExistsException, NotFoundException, NotOwnerException;
    List<Role> listRoles(User owner, UUID orgId) throws NotFoundException, NotOwnerException;
    List<Role> listRoles(User owner, UUID orgId, UUID userId) throws NotFoundException, NotOwnerException;
    User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException;
    User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotOwnerException, NotFoundException, NotAllowedException;

    Permission createPermission(User owner, UUID orgId, String permission, String description) throws NotOwnerException, NotFoundException;
    Set<String> listPermissions(UUID userId) throws NotFoundException;
    Set<Permission> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException;

    Role addPermissionToRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException;
    Role removePermissionFromRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException;
}
