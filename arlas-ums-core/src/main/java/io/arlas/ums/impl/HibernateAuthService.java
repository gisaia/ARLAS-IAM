package io.arlas.ums.impl;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.InvalidParameterException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.ums.config.AuthConfiguration;
import io.arlas.ums.config.InitConfiguration;
import io.arlas.ums.core.*;
import io.arlas.ums.exceptions.*;
import io.arlas.ums.model.*;
import io.arlas.ums.util.ArlasAuthServerConfiguration;
import io.arlas.ums.util.SMTPMailer;
import io.arlas.ums.util.TokenManager;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class HibernateAuthService implements AuthService {
    private final GroupDao groupDao;
    private final OrganisationDao organisationDao;
    private final OrganisationMemberDao organisationMemberDao;
    private final PermissionDao permissionDao;
    private final RoleDao roleDao;
    private final UserDao userDao;
    private final RefreshTokenDao tokenDao;
    private final BCryptPasswordEncoder encoder;
    private final SMTPMailer mailer;
    private final TokenManager tokenManager;
    private final boolean verifyEmail; // set to true in production, false in testing mode
    private final long verifyTokenTtl;
    private final InitConfiguration defaultInitConf;

    private static final ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
    private static final String DEFAULT_CONF_FILE_NAME = "roles.yaml";

    // this regex will do a basic check (verification will be done by sending an email to the user) and extract domain
    private static final Pattern emailRegex = Pattern.compile("(?<=@)[^.]+(?=\\.)");

    public HibernateAuthService(SessionFactory factory, ArlasAuthServerConfiguration conf) {
        this.groupDao = new HibernateGroupDao(factory);
        this.organisationDao = new HibernateOrganisationDao(factory);
        this.organisationMemberDao = new HibernateOrganisationMemberDao(factory);
        this.permissionDao = new HibernatePermissionDao(factory);
        this.roleDao = new HibernateRoleDao(factory);
        this.userDao = new HibernateUserDao(factory);
        this.tokenDao = new HibernateRefreshTokenDao(factory);
        this.encoder = new BCryptPasswordEncoder();
        this.mailer = new SMTPMailer(conf.smtp);
        this.tokenManager = new TokenManager(factory, (AuthConfiguration) conf.arlasAuthConfiguration);
        this.verifyEmail = conf.verifyEmail;
        this.verifyTokenTtl = ((AuthConfiguration)conf.arlasAuthConfiguration).verifyTokenTTL;
        this.defaultInitConf = ((AuthConfiguration) conf.arlasAuthConfiguration).initConfiguration;
    }

    // ------- private ------------

    private String encode(String password) {
        return encoder.encode(password);
    }

    private boolean matches(String inputPassword, String storedPassword) {
        return encoder.matches(inputPassword, storedPassword);
    }

    private Optional<String> validateEmailDomain(String email) {
        Matcher regexMatcher = emailRegex.matcher(email);
        return regexMatcher.find() ? Optional.of(regexMatcher.group()) : Optional.empty();
    }

    private void sendActivationEmail(User user, String token) throws SendEmailException {
        mailer.sendEmail(user, token);
    }

    private Organisation getOrganisation(User owner, UUID orgId, boolean checkOwned)
            throws NotOwnerException, NotFoundException {
        Optional<Organisation> organisation = owner.getOrganisations().stream()
                .filter(om -> (om.getOrganisation().is(orgId)) && (!checkOwned || om.isOwner()))
                .map(OrganisationMember::getOrganisation)
                .findFirst();
        if (organisation.isPresent()) {
            return organisation.get();
        } else {
            if (checkOwned) { throw new NotOwnerException(); }
            else { throw new NotFoundException(); }
        }
    }

    // ------- public ------------

    @Override
    public void initDatabase(InitConfiguration initData) throws ArlasException {
        if (userDao.listUsers().size() == 0) {
            User user = new User(Optional.ofNullable(initData.admin).orElseGet(() -> defaultInitConf.admin));
            user.setPassword(encode(Optional.ofNullable(initData.password).orElseGet(() -> defaultInitConf.password)));
            user.setLocale(Optional.ofNullable(initData.locale).orElseGet(() -> defaultInitConf.locale));
            user.setTimezone(Optional.ofNullable(initData.timezone).orElseGet(() -> defaultInitConf.timezone));
            user.setVerified(true);
            user = userDao.createUser(user);
            user.setRoles(importDefaultConfiguration(user));
            userDao.updateUser(user);
        } else {
            throw new ArlasException("Database is not empty. Init is not allowed.");
        }
    }

    @Override
    public Set<Role> importDefaultConfiguration(User user) throws InvalidParameterException {
        return importConfiguration(user, this.getClass().getClassLoader().getResourceAsStream(DEFAULT_CONF_FILE_NAME));
    }

    @Override
    public Set<Role> importConfiguration(User user, InputStream is) throws InvalidParameterException {
        try {
            Set<Role> dbRoles = new HashSet<>();
            for (Role r : mapper.readValue(is, Role[].class)) {
                if (r.getPermissions() != null) {
                    r.getPermissions().forEach(p -> {
                        p.setSystem(true);
                        permissionDao.createPermission(p);
                    });
                }
                r.setSystem(true);
                r.setUsers(Set.of(user));
                dbRoles.add(roleDao.createRole(r, r.getPermissions()));
            }
            return dbRoles;
        } catch (IOException e) {
            throw new InvalidParameterException("Malformed json input file.");
        }
    }

    @Override
    public User createUser(String email, String locale, String timezone)
            throws InvalidEmailException, AlreadyExistsException, SendEmailException {
        if (validateEmailDomain(email).isPresent()) {
            if (userDao.readUser(email).isEmpty()) {
                User user = new User(email);
                // in testing mode, we set the password to a known value
                String verifyToken = this.verifyEmail ? KeyGenerators.string().generateKey() : "secret";
                user.setPassword(encode(verifyToken));
                user.setLocale(locale);
                user.setTimezone(timezone);
                user.setVerified(!this.verifyEmail);
                // TODO add more attributes as needed
                user = userDao.createUser(user);
                sendActivationEmail(user, verifyToken);
                return user;
            } else {
                throw new AlreadyExistsException("User already exists.");
            }
        } else {
            throw new InvalidEmailException("Email format is not valid.");
        }
    }

    @Override
    public Optional<User> readUser(UUID userId) {
        return userDao.readUser(userId);
    }

    @Override
    public User readUser(UUID userId, boolean checkActiveVerified) throws NotFoundException {
        Optional<User> user = readUser(userId);
        if (user.isPresent() && user.get().isVerified() && user.get().isActive()) {
            return user.get();
        } else {
            throw new NotFoundException("User not found.");
        }
    }

    @Override
    public LoginSession login(String email, String password, String issuer)
            throws ArlasException {
        User user = userDao.readUser(email).orElseThrow(NotFoundException::new);
        if (user.isActive() && user.isVerified() && matches(password, user.getPassword())) {
            LoginSession ls = tokenManager.getLoginSession(user, issuer, new Date());
            tokenDao.createOrUpdate(user.getId(), ls.refreshToken);
            return ls;
        } else {
            // we don't tell the user which of email or password is wrong, to avoid "username enumeration" attack type
            throw new NotFoundException("No matching user/password found.");
        }
    }

    @Override
    public DecodedJWT verifyToken(String token) {
        return tokenManager.verifyToken(token);
    }

    @Override
    public void logout(UUID userId) {
        tokenDao.read(userId).ifPresent(tokenDao::delete);
    }

    @Override
    public LoginSession refresh(User user, String refreshToken, String issuer) throws ArlasException {
        RefreshToken token = tokenDao.read(refreshToken).orElseThrow(() -> new ArlasException("Invalid refresh token."));
        if (user.is(token.getUserId()) && token.getExpiryDate() >= System.currentTimeMillis() / 1000) {
            LoginSession ls = tokenManager.getLoginSession(user, issuer, new Date());
            tokenDao.createOrUpdate(token.getUserId(), ls.refreshToken);
            return ls;
        } else {
            throw new ArlasException("Expired refresh token.");
        }
    }

    @Override
    public String createPermissionToken(String subject, String issuer, Date iat)
            throws ArlasException {
        return tokenManager.createPermissionToken(subject, issuer, iat, listPermissions(UUID.fromString(subject)));
    }

    @Override
    public User updateUser(User user, String oldPassword, String newPassword)
            throws NonMatchingPasswordException {
        if (matches(oldPassword, user.getPassword())) {
            user.setPassword(encode(newPassword));
            return userDao.updateUser(user);
        } else {
            throw new NonMatchingPasswordException("Old password does not match.");
        }
    }

    @Override
    public void deleteUser(UUID userId) {
        readUser(userId).ifPresent(userDao::deleteUser);
    }

    @Override
    public Optional<User> activateUser(UUID userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setActive(true);
            userDao.updateUser(u);
        });
        return user;
    }

    private void generateNewVerificationToken(User user) throws SendEmailException {
        String verifyToken = KeyGenerators.string().generateKey();
        user.setCreationDate(LocalDateTime.now(ZoneOffset.UTC));
        user.setPassword(encode(verifyToken));
        userDao.updateUser(user);
        sendActivationEmail(user, verifyToken);
    }

    @Override
    public Optional<User> verifyUser(UUID userId, String verifyToken, String password) throws AlreadyVerifiedException, NonMatchingPasswordException, ExpiredTokenException, SendEmailException {
        Optional<User> user = readUser(userId);
        if (user.isPresent()) {
            User u = user.get();
            if (u.isVerified()) {
                throw new AlreadyVerifiedException();
            }
            if (u.getCreationDate().toEpochSecond(ZoneOffset.UTC) + this.verifyTokenTtl/1000 <
                    LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)) {
                generateNewVerificationToken(u);
                throw new ExpiredTokenException();
            }
            if (matches(verifyToken, u.getPassword())) {
                u.setPassword(encode(password));
                u.setVerified(true);
                // TODO create personal organisation: what name? avoid email for GPRD
                userDao.updateUser(u);
            } else {
                throw new NonMatchingPasswordException("Verification token does not match");
            }
        }
        return user;
    }

    @Override
    public Optional<User> deactivateUser(UUID userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setActive(false);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public Set<User> listUsers(User user) {
        return organisationDao.listUsers(user);
    }

    @Override
    public Organisation createOrganisation(User owner)
            throws AlreadyExistsException, NotOwnerException {
        String domain = validateEmailDomain(owner.getEmail()).orElseThrow(RuntimeException::new);
        Optional<Organisation> org = organisationDao.readOrganisation(domain);
        if (org.isEmpty()) {
            Organisation organisation = organisationDao.createOrganisation(new Organisation(domain));
            organisationMemberDao.addUserToOrganisation(owner, organisation, true);
            return organisation;
        } else {
            if (org.get().getMembers().stream()
                    .anyMatch(om -> om.getUser().is(owner.getId()) && om.isOwner())) {
                throw new AlreadyExistsException("Organisation already exists.");
            } else {
                throw new NotOwnerException("Organisation already created by another user.");
            }
        }
    }

    @Override
    public void deleteOrganisation(User owner, UUID orgId)
            throws NotOwnerException, NotFoundException {
        organisationDao.deleteOrganisation(getOrganisation(owner, orgId, true));
        // TODO : delete associated resources
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    @Override
    public Organisation addUserToOrganisation(User owner, String email, UUID orgId)
            throws NotOwnerException, NotFoundException {
        return organisationMemberDao.addUserToOrganisation(
                userDao.readUser(email).orElseThrow(NotFoundException::new),
                getOrganisation(owner, orgId, true),
                false);
    }

    @Override
    public Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId)
            throws NotOwnerException, NotFoundException {
        return organisationMemberDao.removeUserFromOrganisation(
                userDao.readUser(userId).orElseThrow(NotFoundException::new),
                getOrganisation(owner, orgId, true));
    }

    @Override
    public Role createRole(User owner, String name, UUID orgId, Set<Permission> permissions)
            throws AlreadyExistsException, NotOwnerException, NotFoundException {
        Organisation organisation = getOrganisation(owner, orgId, true);
        if (organisation.getRoles().stream().anyMatch(r -> r.getName().equals(name))) {
            throw new AlreadyExistsException("Role already exists.");
        } else {
            Role role = roleDao.createRole(new Role(name).addOrganisation(organisation),
                    permissionDao.savePermissions(permissions));
            organisation.addRole(role);
            return role;
        }
    }

    @Override
    public User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId)
            throws NotFoundException, NotOwnerException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        roleDao.addRoleToUser(user,
                ownerOrg.getRoles().stream().filter(r -> r.is(roleId)).findFirst().orElseThrow(NotFoundException::new));
        return user;
    }

    @Override
    public User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId)
            throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        roleDao.removeRoleFromUser(user,
                ownerOrg.getRoles().stream().filter(r -> r.is(roleId)).findFirst().orElseThrow(NotFoundException::new));
        return user;
    }

    @Override
    public Group createGroup(User owner, String name, UUID orgId)
            throws AlreadyExistsException, NotOwnerException, NotFoundException {
        Organisation organisation = getOrganisation(owner, orgId, true);
        if (organisation.getGroups().stream().anyMatch(r -> r.getName().equals(name))) {
            throw new AlreadyExistsException("Group already exists in this organisation.");
        } else {
            Group group = groupDao.createGroup(new Group(name, organisation));
            organisation.addGroup(group);
            return group;
        }
    }

    @Override
    public User addUserToGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        groupDao.addUserToGroup(user,
                ownerOrg.getGroups().stream().filter(g -> g.is(grpId)).findFirst().orElseThrow(NotFoundException::new));
        return user;
    }

    @Override
    public Group removeUserFromGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        return groupDao.removeUserFromGroup(user,
                ownerOrg.getGroups().stream().filter(g -> g.is(grpId)).findFirst().orElseThrow(NotFoundException::new));
    }

    @Override
    public Group addRoleToGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException {
        Organisation org = getOrganisation(owner, orgId, true);
        return groupDao.addRoleToGroup(
                org.getRoles().stream().filter(r -> r.is(roleId)).findFirst().orElseThrow(NotFoundException::new),
                org.getGroups().stream().filter(g -> g.is(grpId)).findFirst().orElseThrow(NotFoundException::new));
    }

    @Override
    public Group removeRoleFromGroup(User owner, UUID orgId, UUID roleId, UUID grpId) throws NotOwnerException, NotFoundException {
        Organisation org = getOrganisation(owner, orgId, true);
        return groupDao.removeRoleFromGroup(
                org.getRoles().stream().filter(r -> r.is(roleId)).findFirst().orElseThrow(NotFoundException::new),
                org.getGroups().stream().filter(g -> g.is(grpId)).findFirst().orElseThrow(NotFoundException::new));
    }

    private Set<String> listPermissions(User user, Organisation org) {
        Set<Permission> permissions = new HashSet<>(user.getPermissions());
        user.getRoles().stream()
                .filter(r -> r.getOrganisations().contains(org))
                .forEach(r -> permissions.addAll(r.getPermissions()));
        user.getGroups().stream()
                .filter(g -> g.getOrganisation().is(org.getId()))
                .forEach(g -> g.getRoles().forEach(r -> permissions.addAll(r.getPermissions())));
        return permissions.stream().map(Permission::getValue).collect(Collectors.toSet());
    }

    @Override
    public Set<String> listPermissions(UUID userId) throws NotFoundException {
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        Set<String> permissions = new HashSet<>();
        for (OrganisationMember org : user.getOrganisations()) {
            permissions.addAll(listPermissions(user, org.getOrganisation()));
        }
        return permissions;
    }

    @Override
    public Set<String> listPermissions(UUID userId, UUID orgId) throws NotOwnerException, NotFoundException {
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        Organisation org = getOrganisation(user, orgId, false);
        return listPermissions(user, org);
    }

    @Override
    public Set<String> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        return listPermissions(user, ownerOrg);
    }

    @Override
    public Permission createPermission(String permission, boolean isSystem) {
        return permissionDao.createPermission(new Permission(permission, isSystem));
    }

    @Override
    public User addPermissionToUser(UUID userId, UUID permissionId)
            throws NotFoundException {
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        Permission permission = permissionDao.readPermission(permissionId).orElseThrow(NotFoundException::new);
        return userDao.addPermissionToUser(user, permission);
    }

    @Override
    public User removePermissionFromUser(UUID userId, UUID permissionId)
            throws NotFoundException {
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        Permission permission = permissionDao.readPermission(permissionId).orElseThrow(NotFoundException::new);
        return userDao.removePermissionFromUser(user, permission);
    }

    @Override
    public Role addPermissionToRole(UUID roleId, UUID permissionId) throws NotFoundException {
        Role role = roleDao.readRole(roleId).orElseThrow(NotFoundException::new);
        Permission permission = permissionDao.readPermission(permissionId).orElseThrow(NotFoundException::new);
        return roleDao.addPermissionToRole(permission, role);
    }

    @Override
    public Role removePermissionFromRole(UUID roleId, UUID permissionId) throws NotFoundException {
        Role role = roleDao.readRole(roleId).orElseThrow(NotFoundException::new);
        Permission permission = permissionDao.readPermission(permissionId).orElseThrow(NotFoundException::new);
        return roleDao.removePermissionFromRole(permission, role);
    }
}
