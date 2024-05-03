package io.arlas.iam.core;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.model.*;
import jakarta.ws.rs.core.HttpHeaders;

import java.util.*;

public interface AuthService {
    void initDatabase();
    User readUser(UUID userId, boolean checkActiveVerified) throws NotFoundException;

    LoginSession login(String email, String password, String issuer) throws ArlasException;
    DecodedJWT verifyToken(String token);
    void logout(UUID userId);
    LoginSession refresh(String userId, String refreshToken, String issuer) throws ArlasException;
    String createPermissionToken(String subject, String orgFilter, String issuer, Date iat) throws ArlasException;
    String createPermissionToken(String keyId, String keySecret, String issuer) throws ArlasException;
    String createPermissionToken(HttpHeaders headers, String orgFilter) throws ArlasException;

    User createUser(String email, String locale, String timezone) throws InvalidEmailException, AlreadyExistsException, SendEmailException;
    User verifyUser(UUID userId, String verifyToken, String password) throws AlreadyVerifiedException, NonMatchingPasswordException, InvalidTokenException, SendEmailException, NotFoundException;
    void askPasswordReset(String email) throws SendEmailException;
    User resetUserPassword(UUID userId, String resetToken, String password) throws SendEmailException, NotFoundException;

    Optional<User> readUser(UUID userId);
    User updateUser(User user, String oldPassword, String newPassword, String firstName, String lastName, String locale, String timezone) throws NonMatchingPasswordException;
    void deleteUser(UUID userId) throws NotAllowedException;

    Optional<User> activateUser(UUID userId);
    Optional<User> deactivateUser(UUID userId) throws NotAllowedException;

    ApiKey createApiKey(User user, UUID ownerId, UUID oid, String name, int ttlInDays, Set<String> roleIds) throws NotAllowedException, NotFoundException;
    void deleteApiKey(User user, UUID ownerId, UUID oid, UUID apiKeyId) throws NotFoundException, NotAllowedException;

    boolean checkOrganisation(User owner);
    Organisation createOrganisation(User user, String name) throws AlreadyExistsException, NotOwnerException, NotFoundException, ForbiddenOrganisationNameException;
    Organisation createOrganisation(User owner) throws AlreadyExistsException, NotOwnerException, NotFoundException, ForbiddenOrganisationNameException;
    void deleteOrganisation(User owner, UUID orgId) throws NotOwnerException, NotFoundException, ForbiddenActionException;
    Set<Organisation> listOrganisations(User user);
    List<String> getOrganisationCollections(User owner, UUID orgId, String token) throws ArlasException;

    Set<OrganisationMember> listOrganisationUsers(User owner, UUID orgId, String roleName) throws NotOwnerException, NotFoundException;
    List<String> listUserEmailsFromOwnDomain(User owner, UUID orgId) throws NotOwnerException, NotFoundException;

    Organisation addUserToOrganisation(User owner, String email, UUID orgId, Set<String> rids) throws NotOwnerException, NotFoundException, AlreadyExistsException, ForbiddenActionException, SendEmailException, InvalidEmailException, NotAllowedException;
    Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId) throws NotOwnerException, NotFoundException, NotAllowedException;

    Role createRole(User owner, String name, String description, UUID orgId) throws AlreadyExistsException, NotFoundException, NotOwnerException;
    Role updateRole(User owner, String name, String description, UUID orgId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException;
    List<Role> listRoles(User owner, UUID orgId) throws NotFoundException, NotOwnerException;
    List<Role> listRoles(User owner, UUID orgId, UUID userId) throws NotFoundException, NotOwnerException;

    Role createGroup(User owner, String name, String description, UUID orgId) throws AlreadyExistsException, NotFoundException, NotOwnerException;
    Role updateGroup(User owner, String name, String description, UUID orgId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException;
    List<Role> listGroups(User owner, UUID orgId) throws NotFoundException, NotOwnerException;
    List<Role> listGroups(User owner, UUID orgId, UUID userId) throws NotFoundException, NotOwnerException;

    User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException;
    User updateRolesOfUser(User owner, UUID orgId, UUID userId, Set<String> rids)
            throws NotFoundException, NotOwnerException, AlreadyExistsException, NotAllowedException, ForbiddenActionException;
    User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId) throws NotOwnerException, NotFoundException, NotAllowedException, ForbiddenActionException;

    Permission createPermission(User owner, UUID orgId, String value, String description) throws NotOwnerException, NotFoundException, AlreadyExistsException;
    Permission createColumnFilter(User user, UUID fromString, List<String> collections, String token) throws ArlasException;
    Permission updatePermission(User owner, UUID orgId, UUID permissionId, String value, String description) throws NotOwnerException, NotFoundException, AlreadyExistsException;
    Permission updateColumnFilter(User owner, UUID orgId, UUID permissionId, List<String> collections, String token) throws ArlasException;
    Set<Permission> listPermissions(User owner, UUID orgId) throws NotOwnerException, NotFoundException;
    List<String> getCollectionsOfColumnFilter(User owner, UUID orgId, UUID permissionId, String token) throws ArlasException;
    Set<Permission> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException;

    Role addPermissionToRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException;
    Role removePermissionFromRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException;

    Set<Permission> listPermissionsOfRole(User owner, UUID orgId, UUID roleId) throws NotOwnerException, NotFoundException;
    Role updatePermissionsOfRole(User owner, UUID orgId, UUID roleId, Set<String> pids) throws NotOwnerException, NotFoundException;

    ForbiddenOrganisation addForbiddenOrganisation(User user, ForbiddenOrganisation name) throws AlreadyExistsException, NotAllowedException;
    List<ForbiddenOrganisation> listForbiddenOrganisation(User user) throws NotAllowedException;
    void removeForbiddenOrganisation(User user, String name) throws NotAllowedException, NotFoundException;

}
