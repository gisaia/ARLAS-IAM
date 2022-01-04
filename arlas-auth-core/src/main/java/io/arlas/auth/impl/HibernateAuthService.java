package io.arlas.auth.impl;

import io.arlas.auth.core.*;
import io.arlas.auth.exceptions.*;
import io.arlas.auth.model.*;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HibernateAuthService implements AuthService {
    private final GroupDao groupDao;
    private final OrganisationDao organisationDao;
    private final OrganisationMemberDao organisationMemberDao;
    private final PermissionDao permissionDao;
    private final RoleDao roleDao;
    private final UserDao userDao;
    private final BCryptPasswordEncoder encoder;

    // this regex will do a basic check (verification will be done by sending an email to the user) and extract domain
    private static final Pattern emailRegex = Pattern.compile("(?<=@)[^.]+(?=\\.)");

    public HibernateAuthService(SessionFactory factory) {
        this.groupDao = new HibernateGroupDao(factory);
        this.organisationDao = new HibernateOrganisationDao(factory);
        this.organisationMemberDao = new HibernateOrganisationMemberDao(factory);
        this.permissionDao = new HibernatePermissionDao(factory);
        this.roleDao = new HibernateRoleDao(factory);
        this.userDao = new HibernateUserDao(factory);
        this.encoder = new BCryptPasswordEncoder();
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

    private void sendActivationEmail(User user) {
        // TODO
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
    public User createUser(String email)
            throws InvalidEmailException, AlreadyExistsException {
        if (validateEmailDomain(email).isPresent()) {
            if (userDao.readUser(email).isEmpty()) {
                User user = new User(email);
                // TODO add more attributes
                sendActivationEmail(user);
                return userDao.createUser(user);
            } else {
                throw new AlreadyExistsException();
            }
        } else {
            throw new InvalidEmailException();
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
            throw new NotFoundException();
        }
    }

    @Override
    public User login(String email, String password)
            throws NotFoundException {
        User user = userDao.readUser(email).orElseThrow(NotFoundException::new);
        if (user.isActive() && matches(password, user.getPassword())) {
            return user;
        } else {
            // we don't tell the user which of email or password is wrong, to avoid "username enumeration" attack type
            throw new NotFoundException();
        }
    }

    @Override
    public User updateUser(User user, String oldPassword, String newPassword)
            throws NonMatchingPasswordException {
        if (matches(oldPassword, user.getPassword())) {
            user.setPassword(encode(newPassword));
            return userDao.updateUser(user);
        } else {
            throw new NonMatchingPasswordException();
        }
    }

    @Override
    public Optional<User> deleteUser(UUID userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(userDao::deleteUser);
        return user;
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
    public Optional<User> verifyUser(UUID userId, String password) {
        // TODO add a token system to validate the verification request (link from verification email)
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            if (!u.isVerified()) {
                u.setPassword(encode(password));
                u.setVerified(true);
                // TODO create personal organisation: what name? avoid email for GPRD
                userDao.updateUser(u);
            }
        });
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
                throw new AlreadyExistsException();
            } else {
                throw new NotOwnerException();
            }
        }
    }

    @Override
    public Organisation deleteOrganisation(User owner, UUID orgId)
            throws NotOwnerException, NotFoundException {
        Organisation organisation = getOrganisation(owner, orgId, true);
        organisationDao.deleteOrganisation(organisation);
        // TODO : delete associated resources
        return organisation;
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
            throw new AlreadyExistsException();
        } else {
            return roleDao.createRole(new Role(name).addOrganisation(organisation), permissions);
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
            throw new AlreadyExistsException();
        } else {
            return groupDao.createGroup(new Group(name, organisation));
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
    public User removeUserFromGroup(User owner, UUID orgId, UUID userId, UUID grpId) throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        groupDao.removeUserFromGroup(user,
                ownerOrg.getGroups().stream().filter(g -> g.is(grpId)).findFirst().orElseThrow(NotFoundException::new));
        return user;
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

    @Override
    public Set<Permission> listPermissions(User owner, UUID orgId, UUID userId) throws NotOwnerException, NotFoundException {
        Organisation ownerOrg = getOrganisation(owner, orgId, true);
        User user = userDao.readUser(userId).orElseThrow(NotFoundException::new);
        getOrganisation(user, orgId, false);
        Set<Permission> permissions = new HashSet<>(user.getPermissions());
        user.getRoles().stream()
                .filter(r -> r.getOrganisations().contains(ownerOrg))
                .forEach(r -> permissions.addAll(r.getPermissions()));
        user.getGroups().stream()
                .filter(g -> g.getOrganisation().is(orgId))
                .forEach(g -> g.getRoles().forEach(r -> permissions.addAll(r.getPermissions())));
        return permissions;
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
