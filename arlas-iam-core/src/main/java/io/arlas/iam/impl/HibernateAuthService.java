package io.arlas.iam.impl;

import com.auth0.jwt.interfaces.DecodedJWT;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.arlas.filter.config.TechnicalRoles.*;

public class HibernateAuthService implements AuthService {
    private final Logger LOGGER = LoggerFactory.getLogger(HibernateAuthService.class);
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
    private final InitConfiguration initConf;
    private User admin;

    private final List<String> systemRoles = Arrays.asList(ROLE_IAM_ADMIN, GROUP_PUBLIC);

    // this regex will do a basic check (verification will be done by sending an email to the user) and extract domain
    private static final Pattern emailRegex = Pattern.compile("(?<=@)[^.]+(?=\\.)");

    public HibernateAuthService(SessionFactory factory, ArlasAuthServerConfiguration conf) {
        this.organisationDao = new HibernateOrganisationDao(factory);
        this.organisationMemberDao = new HibernateOrganisationMemberDao(factory);
        this.permissionDao = new HibernatePermissionDao(factory);
        this.roleDao = new HibernateRoleDao(factory);
        this.userDao = new HibernateUserDao(factory);
        this.tokenDao = new HibernateRefreshTokenDao(factory);
        this.encoder = new BCryptPasswordEncoder();
        this.mailer = new SMTPMailer(conf.smtp);
        this.tokenManager = new TokenManager(factory, conf.arlasAuthConfiguration);
        this.verifyEmail = conf.verifyEmail;
        this.verifyTokenTtl = conf.arlasAuthConfiguration.verifyTokenTTL;
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
        Matcher regexMatcher = emailRegex.matcher(email);
        return regexMatcher.find() ? Optional.of(regexMatcher.group()) : Optional.empty();
    }

    private void sendActivationEmail(User user, String token) throws SendEmailException {
        mailer.sendEmail(user, token);
    }

    private void generateNewVerificationToken(User user) throws SendEmailException {
        String verifyToken = KeyGenerators.string().generateKey();
        user.setCreationDate(LocalDateTime.now(ZoneOffset.UTC));
        user.setPassword(encode(verifyToken));
        userDao.updateUser(user);
        sendActivationEmail(user, verifyToken);
    }

    private String getUserDomain(User user) {
        return validateEmailDomain(user.getEmail()).orElseThrow(RuntimeException::new);
    }

    private String getUserOrg(User user) {
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
            this.admin = userDao.readUser(initConf.admin).get();
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
                .map(s -> roleDao.createRole(new Role(s, true).setUsers(Set.of(admin))))
                .collect(Collectors.toSet());
    }

    private Map<String, List<String>> listRoles(UUID userId) throws NotFoundException {
        Map<String, List<String>> orgRoles = new HashMap();
        // we return a map of {"" -> [ roles...], "orgName1_" -> [ roles...], ...}
        // (the empty key is for cross org roles such as "group/public")
        readUser(userId).orElseThrow(NotFoundException::new).getRoles().stream()
                .forEach(r -> {
                    String orgName = r.getOrganisation().map(o -> o.getName()+"_").orElseGet(String::new);
                    List<String> roles = Optional.ofNullable(orgRoles.get(orgName)).orElseGet(ArrayList::new);
                    roles.add(r.getName());
                    orgRoles.put(orgName, roles);
                });
        return orgRoles;
    }

    // ------- public ------------

    @Override
    public void initDatabase() {
        if (userDao.listUsers().size() == 0) {
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
                String verifyToken = this.verifyEmail ? KeyGenerators.string().generateKey() : "secret";
                user.setPassword(encode(verifyToken));
                user.setLocale(locale);
                user.setTimezone(timezone);
                user.setVerified(!this.verifyEmail);
                user = userDao.createUser(user);
                if (this.verifyEmail) {
                    sendActivationEmail(user, verifyToken);
                } else {
                    try {
                        verifyUser(user.getId(), verifyToken, user.getPassword());
                    } catch (AlreadyVerifiedException | NonMatchingPasswordException | ExpiredTokenException | NotFoundException ignored) {
                    }
                }
                var publicGroup = roleDao.getSystemRoles().stream()
                        .filter(r -> GROUP_PUBLIC.equals(r.getName()))
                        .findFirst().get();
                roleDao.addRoleToUser(user, publicGroup);
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
        return tokenManager.createPermissionToken(subject, issuer, iat,
                listPermissions(UUID.fromString(subject)),
                listRoles(UUID.fromString(subject)));
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
    public User verifyUser(UUID userId, String verifyToken, String password)
            throws AlreadyVerifiedException, NonMatchingPasswordException, ExpiredTokenException, SendEmailException, NotFoundException {
        var u = readUser(userId).orElseThrow(() -> new NotFoundException("User not found."));
        if (u.isVerified()) {
            throw new AlreadyVerifiedException("User already verified.");
        }
        if (u.getCreationDate().toEpochSecond(ZoneOffset.UTC) + this.verifyTokenTtl / 1000 <
                LocalDateTime.now(ZoneOffset.UTC).toEpochSecond(ZoneOffset.UTC)) {
            generateNewVerificationToken(u);
            throw new ExpiredTokenException("Verification token expired.");
        }
        if (matches(verifyToken, u.getPassword())) {
            u.setPassword(encode(password));
            u.setVerified(true);
            userDao.updateUser(u);
            try {
                createOrganisation(u, getUserOrg(u));
            } catch (AlreadyExistsException | NotOwnerException ignored) {
                // cannot happen
            }
        } else {
            throw new NonMatchingPasswordException("Verification token does not match");
        }
        return u;
    }

    @Override
    public Organisation createOrganisation(User owner)
            throws AlreadyExistsException, NotOwnerException {
        return createOrganisation(owner, getUserDomain(owner));
    }

    @Override
    public Organisation createOrganisation(final User user, String name)
            throws AlreadyExistsException, NotOwnerException {
        boolean isAdmin = isAdmin(user);
        if (!isAdmin && !(getUserDomain(user).equals(name) || getUserOrg(user).equals(name))) {
            throw new NotOwnerException("Regular users can only create organisations from their email domain. "
                    + "(user domain '" + getUserDomain(user) + "' != requested domain '" + name + "')");
        }
        Optional<Organisation> org = organisationDao.readOrganisation(name);
        if (org.isEmpty()) {
            Organisation organisation = organisationDao.createOrganisation(new Organisation(name));
            // create default permissions
            var allDataPermission = createPermission(organisation,
                    ArlasClaims.getHeaderColumnFilterDefault(name),
                    "View all organisation's collections' data.");
            // create default roles
            var defaultGroup = createRole(organisation, TechnicalRoles.getDefaultGroup(name),
                    "Default organisation group for dashboard sharing.");
            roleDao.addPermissionToRole(allDataPermission, defaultGroup);
            TechnicalRoles.getTechnicalRolesList().stream()
                    .filter(s -> !systemRoles.contains(s))
                    .forEach(s -> roleDao.createRole(new Role(s, false).setOrganisation(organisation)));
            addUserToOrganisation(user, organisation, true);
            if (!isAdmin) {
                addUserToOrganisation(getAdmin(), organisation, true);
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
            throws NotOwnerException, NotFoundException {
        organisationDao.deleteOrganisation(getOrganisation(owner, orgId));
        // TODO : delete associated resources
    }

    @Override
    public Set<OrganisationMember> listOrganisationUsers(User user, UUID orgId) throws NotOwnerException, NotFoundException {
        return organisationDao.listUsers(getOrganisation(user, orgId));

    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    @Override
    public Organisation addUserToOrganisation(User owner, String email, UUID orgId, Boolean isOwner)
            throws NotOwnerException, NotFoundException, AlreadyExistsException {
        var org = getOrganisation(owner, orgId);
        var user = userDao.readUser(email).orElseThrow(() -> new NotFoundException("User not found."));
        if (org.getMembers().stream().anyMatch(om -> om.getUser().is(user.getId()))) {
            throw new AlreadyExistsException("User is already in organisation.");
        }
        return addUserToOrganisation(user, org, isOwner);
    }

    private Organisation addUserToOrganisation(User user, Organisation org, Boolean isOwner) {
        organisationMemberDao.addUserToOrganisation(user, org, isOwner);
        List<String> userDefaultRoles = List.of(TechnicalRoles.getDefaultGroup(org.getName()), ROLE_ARLAS_USER);
        List<String> ownerDefaultRoles = List.of(ROLE_ARLAS_OWNER, ROLE_ARLAS_BUILDER, ROLE_ARLAS_TAGGER);
        // add default roles
        org.getRoles().stream()
                .filter(r -> userDefaultRoles.contains(r.getName())
                        || (isOwner && ownerDefaultRoles.contains(r.getName())))
                .forEach(r -> roleDao.addRoleToUser(user, r));
        return org;
    }

    @Override
    public Organisation removeUserFromOrganisation(User owner, UUID userId, UUID orgId)
            throws NotOwnerException, NotFoundException, NotAllowedException {
        if (isAdmin(userId)) {
            throw new NotAllowedException("Admin cannot be removed from organisations.");
        }
        Organisation org = getOrganisation(owner, orgId);
        User user = getUser(org, userId);
        return organisationMemberDao.removeUserFromOrganisation(user, org);
    }

    private Role createRole(Organisation organisation, String name, String description)
            throws AlreadyExistsException {
        if (organisation.getRoles().stream().anyMatch(r -> r.getName().equals(name))) {
            throw new AlreadyExistsException("Role already exists.");
        } else {
            Role role = roleDao.createRole(new Role(name, description).setOrganisation(organisation));
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
    public User removeRoleFromUser(User owner, UUID orgId, UUID userId, UUID roleId)
            throws NotOwnerException, NotFoundException, NotAllowedException {
        if (isAdmin(userId)) {
            throw new NotAllowedException("Cannot remove roles from admin user.");
        }
        var user = getUser(getOrganisation(owner, orgId), userId);
        var role = getRole(user, roleId).orElseThrow(() -> new NotFoundException("Role was not assigned to user."));
        roleDao.removeRoleFromUser(user, role);
        return user;
    }

    @Override
    public Set<String> listPermissions(UUID userId) throws NotFoundException {
        var user = readUser(userId).orElseThrow(() -> new NotFoundException("User not found."));
        Set<Permission> permissions = new HashSet<>();
        user.getRoles().forEach(r -> permissions.addAll(r.getPermissions()));
        return permissions.stream().map(Permission::getValue).collect(Collectors.toSet());
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
        var permission = permissionDao.createPermission(new Permission(value, description, org));
        org.getPermissions().add(permission);
        return permission;
    }

    @Override
    public Permission createPermission(User owner, UUID orgId, String value, String description) throws NotOwnerException, NotFoundException {
        return createPermission(getOrganisation(owner, orgId), value, description);
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

}
