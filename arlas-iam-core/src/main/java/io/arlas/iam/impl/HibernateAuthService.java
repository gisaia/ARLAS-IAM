package io.arlas.iam.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.client.ApiException;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.filter.config.InitConfiguration;
import io.arlas.filter.config.TechnicalRoles;
import io.arlas.filter.core.ArlasClaims;
import io.arlas.iam.core.*;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.model.*;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.arlas.iam.util.SMTPMailer;
import io.arlas.iam.util.TokenManager;
import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

import static io.arlas.commons.rest.utils.ServerConstants.NO_ORG;
import static io.arlas.filter.config.TechnicalRoles.*;

public class HibernateAuthService implements AuthService {
    private final Logger LOGGER = LoggerFactory.getLogger(HibernateAuthService.class);
    private final ArlasService arlasService;
    private final ForbiddenOrganisationDao forbiddenOrganisationDao;
    private final OrganisationDao organisationDao;
    private final OrganisationMemberDao organisationMemberDao;
    private final PermissionDao permissionDao;
    private final RoleDao roleDao;
    private final UserDao userDao;
    private final RefreshTokenDao tokenDao;
    private final ApiKeyDao apiKeyDao;
    private final BCryptPasswordEncoder encoder;
    private final SMTPMailer mailer;
    private final TokenManager tokenManager;
    private final boolean verifyEmail; // set to true in production, false in testing mode
    private final long verifyTokenTtl;
    private final long apiKeyMaxTtl;
    private final InitConfiguration initConf;
    private User admin;

    private final List<String> systemRoles = Arrays.asList(ROLE_IAM_ADMIN, ROLE_ARLAS_IMPORTER);


    public HibernateAuthService(SessionFactory factory, ArlasAuthServerConfiguration conf) {
        this.arlasService = new ArlasService(conf);
        this.forbiddenOrganisationDao = new HibernateForbiddenOrganisationDao(factory);
        this.organisationDao = new HibernateOrganisationDao(factory);
        this.organisationMemberDao = new HibernateOrganisationMemberDao(factory);
        this.permissionDao = new HibernatePermissionDao(factory);
        this.roleDao = new HibernateRoleDao(factory);
        this.userDao = new HibernateUserDao(factory);
        this.tokenDao = new HibernateRefreshTokenDao(factory);
        this.apiKeyDao = new HibernateApiKeyDao(factory);
        this.encoder = new BCryptPasswordEncoder();
        this.mailer = new SMTPMailer(conf.smtp);
        this.tokenManager = new TokenManager(factory, conf.arlasAuthConfiguration);
        this.verifyEmail = conf.verifyEmail;
        this.verifyTokenTtl = conf.arlasAuthConfiguration.verifyTokenTTL;
        this.apiKeyMaxTtl = conf.apiKeyMaxTtl;
        this.initConf = conf.arlasAuthConfiguration.initConfiguration;
    }

    // ------- private ------------

    private String encode(String password) {
        return encoder.encode(password);
    }

    private boolean matches(String inputPassword, String storedPassword) {
        return encoder.matches(inputPassword, storedPassword);
    }

    private Optional<String> validateEmailDomain(String email) {
        int idx = email.indexOf("@");
        return idx != -1 ? Optional.of(email.substring(idx + 1)) : Optional.empty();
    }

    private void sendActivationEmail(User user, String token) throws SendEmailException {
        mailer.sendActivationEmail(user, token);
    }

    private void generateNewVerificationToken(User user) throws SendEmailException {
        String verifyToken = KeyGenerators.string().generateKey();
        user.setCreationDate(LocalDateTime.now(ZoneOffset.UTC));
        user.setTempToken(verifyToken);
        userDao.updateUser(user);
        sendActivationEmail(user, verifyToken);
    }

    private String getUserDomain(User user) {
        return validateEmailDomain(user.getEmail()).orElseThrow(RuntimeException::new);
    }

    private String getUserOrgName(User user) {
        // personal organisation of the user
        return user.getId().toString();
    }

    private Organisation getOrganisation(User owner, UUID orgId)
            throws NotOwnerException, NotFoundException {
        if (isAdmin(owner)) {
            return organisationDao.readOrganisation(orgId).orElseThrow(() -> new NotFoundException("Organisation not found."));
        }
        OrganisationMember organisationMember = owner.getOrganisations().stream()
                .filter(om -> om.getOrganisation().is(orgId))
                .findFirst()
                .orElseThrow(() -> new NotOwnerException("User does not belong to organisation."));
        if (organisationMember.isOwner()) {
            return organisationMember.getOrganisation();
        } else {
            throw new NotOwnerException("User is not owner of the organisation");
        }
    }

    private User getUser(Organisation org, UUID userId) throws NotFoundException {
        return org.getMembers().stream()
                .filter(om -> om.getUser().is(userId))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("User not found in organisation."))
                .getUser();
    }

    private Role getRole(Organisation org, UUID roleId) throws NotFoundException {
        return org.getRoles().stream()
                .filter(r -> r.is(roleId))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Role not found in organisation."));
    }

    private Optional<Role> getRole(User user, UUID roleId) {
        return user.getRoles().stream()
                .filter(r -> r.is(roleId))
                .findFirst();
    }

    private Permission getPermission(Organisation org, UUID permissionId) throws NotFoundException {
        return org.getPermissions().stream()
                .filter(p -> p.is(permissionId))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Permission not found in organisation."));
    }

    private Permission getPermission(Role role, UUID permissionId) throws NotFoundException {
        return role.getPermissions().stream()
                .filter(p -> p.is(permissionId))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Permission not found in role."));
    }

    private User getAdmin() {
        if (this.admin == null) {
            // admin has been created at application startup so it must exist
            this.admin = userDao.readUser(initConf.admin).orElseGet(() -> new User(initConf.admin));
        }
        return this.admin;
    }

    private boolean isAdmin(UUID userId) {
        return getAdmin().is(userId);
    }

    private boolean isAdmin(User user) {
        return isAdmin(user.getId());
    }

    private Set<Role> importDefaultAdminRole(User admin) {
        return TechnicalRoles.getTechnicalRolesList().stream()
                .filter(systemRoles::contains)
                .map(s -> roleDao.createOrUpdateRole(new Role(s, true).setUsers(Set.of(admin)).setTechnical(true)))
                .collect(Collectors.toSet());
    }

    private Map<String, List<String>> listRoles(UUID userId, String orgFilter) throws NotFoundException {
        return listRoles(readUser(userId).orElseThrow(NotFoundException::new).getRoles(), orgFilter);
    }

    private Map<String, List<String>> listRoles(Set<Role> roles, String orgFilter) throws NotFoundException {
        Map<String, List<String>> orgRoles = new HashMap<>();
        // we return a map of {"" -> [ roles...], "orgName1" -> [ roles...], ...}
        // (the empty key is for cross org roles such as "role/iam/admin")
        roles.forEach(r -> {
            String orgName = r.getOrganisation().map(Organisation::getName).orElse(NO_ORG);
            if (orgFilter == null || orgName.equals(orgFilter) || orgName.equals(NO_ORG)) {
                List<String> roleList = Optional.ofNullable(orgRoles.get(orgName)).orElseGet(ArrayList::new);
                roleList.add(r.getName());
                orgRoles.put(orgName, roleList);
            }
        });
        // manually add "group/public" which is given to everybody
        List<String> publicRole = Optional.ofNullable(orgRoles.get(NO_ORG)).orElseGet(ArrayList::new);
        publicRole.add(GROUP_PUBLIC);
        orgRoles.put(NO_ORG, publicRole);
        return orgRoles;
    }

    // ------- public ------------

    @Override
    public void initDatabase() {
        if (userDao.listUsers().isEmpty()) {
            LOGGER.info("***** Database is empty. Init is executed.");
            User admin = new User(initConf.admin);
            admin.setPassword(encode(initConf.password));
            admin.setLocale(initConf.locale);
            admin.setTimezone(initConf.timezone);
            admin.setVerified(true);
            admin = userDao.createUser(admin);
            admin.setRoles(importDefaultAdminRole(admin));
            this.admin = userDao.updateUser(admin);
        } else {
            LOGGER.info("***** Database is not empty. Init is skipped.");
        }
    }

    @Override
    public User createUser(String email, String locale, String timezone)
            throws InvalidEmailException, AlreadyExistsException, SendEmailException {
        if (validateEmailDomain(email).isPresent()) {
            if (userDao.readUser(email).isEmpty()) {
                var user = new User(email);
                // in testing mode, we set the password to a known value
                String verifyToken = KeyGenerators.string().generateKey();
                user.setTempToken(verifyToken);
                if (!this.verifyEmail) {
                    user.setPassword(encode("secret"));
                }
                user.setLocale(locale != null ? locale : Locale.ENGLISH.toString());
                user.setTimezone(timezone != null ? timezone : "Europe/Paris");
                user.setVerified(!this.verifyEmail);
                user = userDao.createUser(user);
                if (this.verifyEmail) {
                    sendActivationEmail(user, verifyToken);
                } else {
                    try {
                        createOrganisation(user, getUserOrgName(user));
                    } catch (AlreadyExistsException | NotOwnerException | ForbiddenOrganisationNameException ignored) {
                    }
                }
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
        var user = userDao.readUser(email).orElseThrow(() -> new NotFoundException("No matching user/password found."));
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
    public LoginSession refresh(String authHeader, String refreshToken, String issuer) throws ArlasException {
        if (authHeader == null || !authHeader.toLowerCase().startsWith("bearer ")) {
            throw new InvalidTokenException("Invalid access token: " + authHeader);
        }
        User user = null;
        try {
            String accessToken = authHeader.substring(7);
            DecodedJWT t = JWT.decode(accessToken);
            user = readUser(UUID.fromString(t.getSubject()), true);
        } catch (JWTDecodeException e) {
            throw new InvalidTokenException("Invalid access token: " + authHeader, e);
        }

        RefreshToken token = tokenDao.read(refreshToken).orElseThrow(() -> new InvalidTokenException("Invalid refresh token."));
        if (user.is(token.getUserId()) && token.getExpiryDate() >= System.currentTimeMillis() / 1000) {
            LoginSession ls = tokenManager.getLoginSession(user, issuer, new Date());
            tokenDao.createOrUpdate(token.getUserId(), ls.refreshToken);
            return ls;
        } else {
            throw new InvalidTokenException("Expired refresh token.");
        }
    }

    @Override
    public String createPermissionToken(String subject, String orgFilter, String issuer, Date iat)
            throws ArlasException {
        LOGGER.info("Getting permission token with orgFilter="+orgFilter);
        return tokenManager.createPermissionToken(subject, issuer, iat,
                listPermissions(UUID.fromString(subject), orgFilter),
                listRoles(UUID.fromString(subject), orgFilter));
    }

    @Override
    public ApiKey createApiKey(User user, UUID ownerId, UUID orgId, String name, int ttlInDays, Set<String> roleIds) throws NotAllowedException, NotFoundException {
        if (user.is(ownerId) || isAdmin(user)) {
            var org = organisationDao.readOrganisation(orgId).orElseThrow(() -> new NotFoundException("Organisation not found."));
            var secret = KeyGenerators.string().generateKey();
            Set<Role> roles = roleIds.stream()
                    .map(id -> roleDao.readRole(UUID.fromString(id)).get())
                    .collect(Collectors.toSet());
            ApiKey apiKey = new ApiKey(name,
                    KeyGenerators.string().generateKey(),
                    encode(secret),
                    (int) Math.min(apiKeyMaxTtl, ttlInDays),
                    user,
                    org,
                    roles);
            apiKeyDao.createApiKey(apiKey);
            roles.forEach(r -> { r.addApiKeys(apiKey); roleDao.createOrUpdateRole(r); });
            return new ApiKey(name, apiKey.getKeyId(), secret, apiKey.getTtlInDays(), user, org, apiKey.getRoles());
        } else {
            throw new NotAllowedException("Only owner or admin can create this key.");
        }
    }

    @Override
    public void deleteApiKey(User user, UUID ownerId, UUID oid, UUID apiKeyId) throws NotFoundException, NotAllowedException {
        if (user.is(ownerId) || isAdmin(user)) {
            ApiKey apiKey = user.getApiKeys().stream()
                    .filter(k -> k.getId().equals(apiKeyId))
                    .findFirst()
                    .orElseThrow(NotFoundException::new);
            apiKeyDao.deleteApiKey(apiKey);
        } else {
            throw new NotAllowedException("Only owner or admin can delete this key.");
        }
    }

    @Override
    public String createPermissionToken(String keyId, String keySecret, String issuer) throws ArlasException {
        ApiKey key = apiKeyDao.readApiKey(keyId).orElseThrow(NotFoundException::new);
        if (key.getCreationDate().toEpochSecond(ZoneOffset.UTC) + (long) key.getTtlInDays()*24*60*60
                > LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)
                && matches(keySecret, key.getKeySecret())) {
            return tokenManager.createPermissionToken(key.getOwner().getId().toString(), issuer, new Date(),
                    listPermissions(key.getRoles(), null),
                    listRoles(key.getRoles(), null));
        } else {
            throw new ExpiredKeyException();
        }
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
    public void deleteUser(UUID userId) throws NotAllowedException {
        if (isAdmin(userId)) {
            throw new NotAllowedException("Admin cannot be removed from database.");
        }
        readUser(userId).ifPresent(userDao::deleteUser);
        // TODO: delete user resources (organisation, collections...)
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

    @Override
    public Optional<User> deactivateUser(UUID userId) throws NotAllowedException {
        if (isAdmin(userId)) {
            throw new NotAllowedException("Admin cannot be deactivated.");
        }
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setActive(false);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public void askPasswordReset(String email) throws SendEmailException {
        Optional<User> user = userDao.readUser(email);
        if (user.isPresent()) {
            var u = user.get();
            String resetToken = KeyGenerators.string().generateKey();
            u.setTempToken(resetToken);
            userDao.updateUser(u);
            mailer.sendPasswordResetEmail(u, resetToken);
        }
    }

    @Override
    public User resetUserPassword(UUID userId, String resetToken, String password) throws NotFoundException {
        var u = readUser(userId).orElseThrow(() -> new NotFoundException("User not found."));
        if (resetToken.equals(u.getTempToken())) {
            u.setPassword(encode(password));
            u.setTempToken(null);
            userDao.updateUser(u);
        }
        return u;
    }

    @Override
    public boolean checkOrganisation(User owner) {
        return organisationDao.readOrganisation(getUserDomain(owner)).isPresent();
    }

    @Override
    public User verifyUser(UUID userId, String verifyToken, String password)
            throws AlreadyVerifiedException, NonMatchingPasswordException, InvalidTokenException, SendEmailException, NotFoundException {
        var u = readUser(userId).orElseThrow(() -> new NotFoundException("User not found."));
        if (u.isVerified()) {
            throw new AlreadyVerifiedException("User already verified.");
        }
        if (u.getCreationDate().toEpochSecond(ZoneOffset.UTC) + this.verifyTokenTtl / 1000 <
                LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)) {
            generateNewVerificationToken(u);
            throw new InvalidTokenException("Verification token expired.");
        }
        if (verifyToken.equals(u.getTempToken())) {
            u.setPassword(encode(password));
            u.setVerified(true);
            u.setTempToken(null);
            userDao.updateUser(u);
            try {
                createOrganisation(u, getUserOrgName(u));
            } catch (AlreadyExistsException | NotOwnerException | ForbiddenOrganisationNameException ignored) {
                // cannot happen
            }
        } else {
            throw new NonMatchingPasswordException("Verification token does not match");
        }
        return u;
    }

    @Override
    public Organisation createOrganisation(User owner)
            throws AlreadyExistsException, NotOwnerException, ForbiddenOrganisationNameException {
        return createOrganisation(owner, getUserDomain(owner));
    }

    @Override
    public Organisation createOrganisation(final User user, String name)
            throws AlreadyExistsException, NotOwnerException, ForbiddenOrganisationNameException {
        boolean isAdmin = isAdmin(user);
        if (!isAdmin && !(getUserDomain(user).equals(name) || getUserOrgName(user).equals(name))) {
            throw new NotOwnerException("Regular users can only create organisations from their email domain. "
                    + "(user domain '" + getUserDomain(user) + "' != requested domain '" + name + "')");
        }

        if (forbiddenOrganisationDao.getName(name).isPresent()) {
            throw new ForbiddenOrganisationNameException("This organisation name cannot be used.");
        }

        Optional<Organisation> org = organisationDao.readOrganisation(name);
        if (org.isEmpty()) {
            var newOrg = new Organisation(name);
            if (getUserOrgName(user).equals(name)) {
                newOrg.setDisplayName(user.getEmail().substring(0, user.getEmail().indexOf("@")));
            }
            Organisation organisation = organisationDao.createOrganisation(newOrg);
            // create default permissions
            var allDataPermission = createPermission(organisation,
                    ArlasClaims.getHeaderColumnFilterDefault(""),
                    "View all collections' data");

            // create default roles
            var defaultGroup = createRole(organisation, TechnicalRoles.getDefaultGroup(name),
                    "Default organisation group for dashboard sharing.");
            defaultGroup.setTechnical(true);
            roleDao.createOrUpdateRole(defaultGroup);
            roleDao.addPermissionToRole(allDataPermission, defaultGroup);

            Set<String> userDefaultRoles = new HashSet<>();
            userDefaultRoles.add(defaultGroup.getId().toString());
            Map<String, Map<String, List<String>>> technicalRoles = getTechnicalRolesPermissions();
            for (String s : technicalRoles.keySet()) {
                if (!systemRoles.contains(s) && !GROUP_PUBLIC.equals(s)) {
                    Role r = roleDao.createOrUpdateRole(new Role(s, technicalRoles.get(s).get("description").get(0), true).setOrganisation(organisation));
                    userDefaultRoles.add(r.getId().toString());
                }
            }
            try {
                addUserToOrganisation(user, user, organisation, userDefaultRoles, true);
                if (!isAdmin) {
                    addUserToOrganisation(user, getAdmin(), organisation, userDefaultRoles, true);
                }
            } catch (NotAllowedException | ForbiddenActionException | NotFoundException e) {
                LOGGER.warn("Cannot add user to org.", e);
            }
            return organisation;
        } else {
            if (org.get().getMembers().stream().anyMatch(om -> om.getUser().is(user.getId()) && om.isOwner())) {
                throw new AlreadyExistsException("Organisation already exists.");
            } else {
                throw new NotOwnerException("Organisation already created by another user.");
            }
        }
    }

    @Override
    public void deleteOrganisation(User owner, UUID orgId)
            throws NotOwnerException, NotFoundException, ForbiddenActionException {
        var org = getOrganisation(owner, orgId);
        if (org.getName().equals(owner.getId().toString())) {
            throw new ForbiddenActionException("Cannot delete own organisation.");
        }
        organisationDao.deleteOrganisation(org);
        // TODO : delete associated resources
    }

    private Set<OrganisationMember> listOrganisationUsers(User owner, UUID orgId) throws NotOwnerException, NotFoundException {
        return listOrganisationUsers(owner, orgId, Optional.empty(), true);
    }

    @Override
    public Set<OrganisationMember> listOrganisationUsers(User owner, UUID orgId, Optional<String> roleName) throws NotOwnerException, NotFoundException {
        return listOrganisationUsers(owner, orgId, roleName, false);
    }

    private Set<OrganisationMember> listOrganisationUsers(User owner, UUID orgId, Optional<String> roleName, boolean showAdmin) throws NotOwnerException, NotFoundException {
        return organisationDao.listUsers(getOrganisation(owner, orgId))
                .stream()
                .filter(m -> showAdmin || !isAdmin(m.getUser()))
                .filter(m -> {
                    try {
                        return roleName.isEmpty() || listRoles(owner, orgId, m.getUser().getId()).stream().anyMatch(r -> r.getName().equals(roleName.get()));
                    } catch (NotFoundException | NotOwnerException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toSet());

    }

    @Override
    public List<String> listUserEmailsFromOwnDomain(User owner, UUID orgId) throws NotOwnerException, NotFoundException {
        var org = getOrganisation(owner, orgId);

        List<User> result = userDao.listUsers(org.getName());
        result.removeAll(org.getMembers().stream().map(OrganisationMember::getUser).toList());
        result.remove(getAdmin());
        return result.stream().map(User::getEmail).sorted().toList();
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    @Override
    public List<String> getOrganisationCollections(User owner, UUID orgId, String token) throws ArlasException {
        var org = getOrganisation(owner, orgId);
        try {
            return arlasService.getCollections(org.getName(), token);
        } catch (ApiException e) {
            throw new ArlasException("Error contacting Arlas Server:" + e.getMessage());
        }
    }

    @Override
    public Organisation addUserToOrganisation(User owner, String email, UUID orgId, Set<String> rids)
            throws NotOwnerException, NotFoundException, AlreadyExistsException, ForbiddenActionException, SendEmailException, InvalidEmailException, NotAllowedException {
        var org = getOrganisation(owner, orgId);
        if (org.getName().equals(owner.getId().toString())) {
            throw new ForbiddenActionException("Cannot invite users in own organisation.");
        }
        var user = userDao.readUser(email).orElse(null);
        if (user == null) {
            user = createUser(email, null, null);
        }
        final var uid = user.getId();
        if (org.getMembers().stream().anyMatch(om -> om.getUser().is(uid))) {
            throw new AlreadyExistsException("User is already in organisation.");
        }
        return addUserToOrganisation(owner, user, org, rids);
    }
    
    private Organisation addUserToOrganisation(User owner, User user, Organisation org, Set<String> rids) throws NotOwnerException, AlreadyExistsException, NotAllowedException, ForbiddenActionException, NotFoundException {
        return addUserToOrganisation(owner, user, org, rids, false);
    }

    private Organisation addUserToOrganisation(User owner, User user, Organisation org, Set<String> rids, boolean isOwner) throws NotOwnerException, AlreadyExistsException, NotAllowedException, ForbiddenActionException, NotFoundException {
        Organisation o = organisationMemberDao.addUserToOrganisation(user, org, isOwner, isAdmin(user));

        updateRolesOfUser(owner, org.getId(), user.getId(), rids);
        return o;
    }

    @Override
    public Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId)
            throws NotOwnerException, NotFoundException {
        Organisation org = getOrganisation(owner, orgId);
        User user = getUser(org, userId);
        listRoles(owner, orgId, userId).forEach(r -> roleDao.removeRoleFromUser(user, r));
        return organisationMemberDao.removeUserFromOrganisation(user, org);
    }

    private Role createRole(Organisation organisation, String name, String description)
            throws AlreadyExistsException {
        if (organisation.getRoles().stream().anyMatch(r -> r.getName().equals(name))) {
            throw new AlreadyExistsException("Role already exists.");
        } else {
            Role role = roleDao.createOrUpdateRole(new Role(name, description).setOrganisation(organisation));
            organisation.addRole(role);
            return role;
        }
    }

    @Override
    public Role createRole(User owner, String name, String description, UUID orgId)
            throws AlreadyExistsException, NotOwnerException, NotFoundException {
        return createRole(getOrganisation(owner, orgId), name, description);
    }

    @Override
    public Role updateRole(User owner, String name, String description, UUID orgId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        Organisation org = getOrganisation(owner, orgId);
        Set<Role> orgRoles = org.getRoles();
        Role role = orgRoles.stream().filter(r -> r.getId().equals(roleId)).findFirst().orElseThrow(NotFoundException::new);

        if (role.isTechnical()) {
            throw new ForbiddenActionException("Cannot modify technical roles.");
        }
        if (orgRoles.stream().anyMatch(r -> r.getName().equals(name) && !r.getId().equals(roleId))) {
            throw new AlreadyExistsException("A role with same name already exists in organisation.");
        }
        return roleDao.createOrUpdateRole(role.setName(name).setDescription(description));
    }

    @Override
    public List<Role> listRoles(User owner, UUID orgId) throws NotOwnerException, NotFoundException {
        return getOrganisation(owner, orgId).getRoles().stream().toList();
    }

    @Override
    public List<Role> listRoles(User owner, UUID orgId, UUID userId) throws NotFoundException, NotOwnerException {
        var org = getOrganisation(owner, orgId);
        var user = getUser(org, userId);
        return user.getRoles().stream()
                .filter(r -> org.is(r.getOrganisation().orElse(null)) || r.isSystem())
                .sorted(Comparator.comparing(Role::getName))
                .toList();
    }

    @Override
    public Role createGroup(User owner, String name, String description, UUID orgId)
            throws AlreadyExistsException, NotOwnerException, NotFoundException {
        var org = getOrganisation(owner, orgId);
        Role group = createRole(org, TechnicalRoles.getNewDashboardGroupRole(org.getName(), name), description);
        for (OrganisationMember om : org.getMembers().stream().filter(OrganisationMember::isOwner).toList()) {
            addRoleToUser(owner, orgId, om.getUser().getId(), group.getId());
        }
        return group;
    }

    @Override
    public Role updateGroup(User owner, String name, String description, UUID orgId, UUID roleId) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        var org = getOrganisation(owner, orgId);
        return updateRole(owner, TechnicalRoles.getNewDashboardGroupRole(org.getName(), name), description, orgId, roleId);
    }

    @Override
    public List<Role> listGroups(User owner, UUID orgId) throws NotOwnerException, NotFoundException {
        return listRoles(owner, orgId).stream().filter(Role::isGroup).toList();
    }

    @Override
    public List<Role> listGroups(User owner, UUID orgId, UUID userId) throws NotFoundException, NotOwnerException {
        return listRoles(owner, orgId, userId).stream().filter(Role::isGroup).toList();
    }

    @Override
    public User addRoleToUser(User owner, UUID orgId, UUID userId, UUID roleId)
            throws NotFoundException, NotOwnerException, AlreadyExistsException {
        var org = getOrganisation(owner, orgId);
        var user = getUser(org, userId);
        if (getRole(user, roleId).isPresent()) {
            throw new AlreadyExistsException("Role is already assigned to user.");
        }
        var role = roleDao.readRole(roleId).orElseThrow(() -> new NotFoundException("Role not found."));
        if (role.isSystem() || org.getRoles().stream().anyMatch(r -> r.is(roleId))) {
            roleDao.addRoleToUser(user, role);
            return user;
        } else {
            throw new NotFoundException("Role not found in organisation");
        }
    }

    @Override
    public User updateRolesOfUser(User owner, UUID orgId, UUID userId, Set<String> newRoles)
            throws NotFoundException, NotOwnerException, AlreadyExistsException, NotAllowedException, ForbiddenActionException {
        var org = getOrganisation(owner, orgId);
        var member = listOrganisationUsers(owner, orgId).stream()
                .filter(om -> om.getUser().is(userId))
                .findFirst()
                .orElseThrow(NotFoundException::new);
        var user = member.getUser();

        List<String> currentRoles = user.getRoles().stream()
                .filter(r ->
                        org.is(r.getOrganisation().orElse(null)))
                .map(r -> r.getId().toString())
                .toList();

        List<String> addedRoles = new ArrayList<>(newRoles);
        addedRoles.removeAll(currentRoles);
        List<String> deletedRoles = new ArrayList<>(currentRoles);
        deletedRoles.removeAll(newRoles);

        for (String r : addedRoles) {
            addRoleToUser(owner, orgId, userId, UUID.fromString(r));
        }
        for (String r : deletedRoles) {
            removeRoleFromUser(owner, orgId, userId, UUID.fromString(r));
        }

        member.setOwner(newRoles.stream()
                .map(r -> roleDao.readRole(UUID.fromString(r)).get().getName())
                .anyMatch(n -> n.equals(ROLE_ARLAS_OWNER)));

        return getUser(org, userId);
    }

    @Override
    public User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId)
            throws NotOwnerException, NotFoundException, NotAllowedException, ForbiddenActionException {
        if (isAdmin(userId)) {
            throw new NotAllowedException("Cannot remove roles from admin user.");
        }
        var org = getOrganisation(owner, orgId);
        var user = getUser(org, userId);
        var role = getRole(user, roleId).orElseThrow(() -> new NotFoundException("Role was not assigned to user."));
        if (owner.is(userId) && role.getName().equals(TechnicalRoles.getDefaultGroup(org.getName()))) {
            throw new ForbiddenActionException("Owner cannot remove themselves from the default group of their organisation.");
        }
        if (owner.is(userId) && role.getName().equals(ROLE_ARLAS_OWNER)) {
            throw new ForbiddenActionException("Owner cannot remove their own 'owner' role.");
        }
        roleDao.removeRoleFromUser(user, role);
        return user;
    }

    private Set<String> listPermissions(UUID userId, String orgFilter) throws NotFoundException {
        return listPermissions(readUser(userId).orElseThrow(() -> new NotFoundException("User not found.")).getRoles(), orgFilter);

    }
    private Set<String> listPermissions(Set<Role> roles, String orgFilter) throws NotFoundException {
        Set<Permission> permissions = new HashSet<>();
        roles.forEach(r -> {
            String orgName = r.getOrganisation().map(Organisation::getName).orElse(NO_ORG);
            if (orgFilter == null || orgName.equals(orgFilter) || orgName.equals(NO_ORG)) {
                permissions.addAll(r.getPermissions());
            }
        });

        return permissions.stream().map(Permission::getValue).collect(Collectors.toSet());
    }

    @Override
    public Set<Permission> listPermissions(User owner, UUID orgId) throws NotOwnerException, NotFoundException {
        return getOrganisation(owner, orgId).getPermissions();
    }

    @Override
    public List<String> getCollectionsOfColumnFilter(User owner, UUID orgId, UUID permissionId, String token) throws ArlasException {
        var org = getOrganisation(owner, orgId);
        List<String> collections = ArlasClaims.extractCollections(getPermission(org, permissionId).getValue());

        if (collections.contains(org.getName() + "_*")) {
            return getOrganisationCollections(owner, orgId, token);
        } else {
            return collections;
        }
    }

    @Override
    public Set<Permission> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException {
        var org = getOrganisation(owner, orgId);
        var user = getUser(org, userId);
        Set<Permission> permissions = new HashSet<>();
        user.getRoles().stream()
                .filter(r -> org.is(r.getOrganisation().orElse(null)))
                .forEach(r -> permissions.addAll(r.getPermissions()));
        return permissions;
    }

    private Permission createPermission(Organisation org, String value, String description) {
        var permission = permissionDao.createOrUpdatePermission(new Permission(value, description, org));
        org.getPermissions().add(permission);
        return permission;
    }

    @Override
    public Permission createPermission(User owner, UUID orgId, String value, String description) throws NotOwnerException, NotFoundException, AlreadyExistsException {
        if (listPermissions(owner, orgId).stream().anyMatch(p -> p.getValue().equals(value))) {
            throw new AlreadyExistsException("Permission already exists in organisation.");
        }
        return createPermission(getOrganisation(owner, orgId), value, description);
    }

    private void checkServerCollections(User owner, UUID orgId, List<String> collections, String token) throws ArlasException {
        List<String> serverCollections = getOrganisationCollections(owner, orgId, token);
        List<String> targetCollections = new ArrayList<>(collections);
        targetCollections.removeAll(serverCollections);
        if (!targetCollections.isEmpty()) {
            throw new ForbiddenActionException("Collections not available on server: " + targetCollections);
        }
    }

    @Override
    public Permission createColumnFilter(User owner, UUID orgId, List<String> collections, String token) throws ArlasException {
        checkServerCollections(owner, orgId, collections, token);
        String value = ArlasClaims.getHeaderColumnFilter(collections);
        return createPermission(owner, orgId, value, String.join(" ", collections));
    }

    @Override
    public Permission updatePermission(User owner, UUID orgId, UUID permissionId, String value, String description) throws NotOwnerException, NotFoundException, AlreadyExistsException {
        Set<Permission> permissions = listPermissions(owner, orgId);
        if (permissions.stream().anyMatch(p -> p.getValue().equals(value) && !p.getId().equals(permissionId))) {
            throw new AlreadyExistsException("Permission already exists in organisation.");
        }
        Permission permission = permissions.stream()
                .filter(p -> p.is(permissionId))
                .findFirst()
                .orElseThrow(() -> new NotFoundException("Permission not found in organisation."));
        return permissionDao.createOrUpdatePermission(permission.setValue(value).setDescription(description));
    }

    @Override
    public Permission updateColumnFilter(User owner, UUID orgId, UUID permissionId, List<String> collections, String token) throws ArlasException {
        checkServerCollections(owner, orgId, collections, token);
        String value = ArlasClaims.getHeaderColumnFilter(collections);
        return updatePermission(owner, orgId, permissionId, value, String.join(" ", collections));
    }

    @Override
    public Role addPermissionToRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException {
        var org = getOrganisation(owner, orgId);
        var role = getRole(org, roleId);
        var permission = getPermission(org, permissionId);
        return roleDao.addPermissionToRole(permission, role);
    }

    @Override
    public Role removePermissionFromRole(User owner, UUID orgId, UUID roleId, UUID permissionId) throws NotFoundException, NotOwnerException {
        var role = getRole(getOrganisation(owner, orgId), roleId);
        var permission = getPermission(role, permissionId);
        return roleDao.removePermissionFromRole(permission, role);
    }

    @Override
    public Set<Permission> listPermissionsOfRole(User owner, UUID orgId, UUID roleId) throws NotOwnerException, NotFoundException {
        var org = getOrganisation(owner, orgId);
        var role = getRole(org, roleId);
        return role.getPermissions();
    }

    @Override
    public Role updatePermissionsOfRole(User owner, UUID orgId, UUID roleId, Set<String> pids) throws NotOwnerException, NotFoundException {
        var org = getOrganisation(owner, orgId);
        var role = getRole(org, roleId);
        List<String> currentPermissions = role.getPermissions().stream()
                .map(p -> p.getId().toString())
                .toList();

        List<String> addedPermissions = new ArrayList<>(pids);
        addedPermissions.removeAll(currentPermissions);
        List<String> deletedPermissions = new ArrayList<>(currentPermissions);
        deletedPermissions.removeAll(pids);

        for (String p : addedPermissions) {
            addPermissionToRole(owner, orgId, roleId, UUID.fromString(p));
        }
        for (String p : deletedPermissions) {
            removePermissionFromRole(owner, orgId, roleId, UUID.fromString(p));
        }

        return getRole(org, roleId);
    }

    @Override
    public ForbiddenOrganisation addForbiddenOrganisation(User user, ForbiddenOrganisation name) throws NotAllowedException {
        if (!isAdmin(user)) {
            throw new NotAllowedException("Only super admin can do this action.");
        }
        return forbiddenOrganisationDao.addName(name);
    }

    @Override
    public List<ForbiddenOrganisation> listForbiddenOrganisation(User user) throws NotAllowedException {
        if (!isAdmin(user)) {
            throw new NotAllowedException("Only super admin can do this action.");
        }
        return forbiddenOrganisationDao.listNames();
    }

    @Override
    public void removeForbiddenOrganisation(User user, String name) throws NotAllowedException, NotFoundException {
        if (!isAdmin(user)) {
            throw new NotAllowedException("Only super admin can do this action.");
        }
        forbiddenOrganisationDao.removeName(forbiddenOrganisationDao.getName(name).orElseThrow(NotFoundException::new));
    }

}
