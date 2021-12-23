package io.arlas.auth.impl;

import io.arlas.auth.core.*;
import io.arlas.auth.exceptions.*;
import io.arlas.auth.model.*;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.*;
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

    @Override
    public User createUser(String email) throws InvalidEmailException, AlreadyExistsException {
        if (validateEmailDomain(email).isPresent()) {
            if (userDao.readUser(email).isEmpty()) {
                User user = new User();
                user.setEmail(email);
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

    private void sendActivationEmail(User user) {
        // TODO
    }

    @Override
    public Optional<User> readUser(UUID userId) {
        return userDao.readUser(userId);
    }

    @Override
    public User login(String email, String password) throws NotFoundException {
        Optional<User> user = userDao.readUser(email);
        if (user.isPresent() && user.get().isActive() && matches(password, user.get().getPassword())) {
            return user.get();
        } else {
            // we don't tell the user which of email or password is wrong, to avoid "username enumeration" attack type
            throw new NotFoundException();
        }
    }

    @Override
    public User updateUser(User user, String oldPassword, String newPassword) throws NonMatchingPasswordException {
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
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setPassword(encode(password));
            u.setVerified(true);
            userDao.updateUser(u);
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
    public Organisation createOrganisation(User owner) throws AlreadyExistsException, NotOwnerException {
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
    public Organisation deleteOrganisation(User user, UUID orgId) throws NotOwnerException {
        Organisation organisation = getOwnedOrganisation(user, orgId, true);
        organisationDao.deleteOrganisation(organisation);
        // TODO : delete associated resources
        return organisation;
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    private Organisation getOwnedOrganisation(User owner, UUID orgId, boolean checkOwned) throws NotOwnerException {
        return owner.getOrganisations().stream()
                .filter(om -> (om.getOrganisation().is(orgId)) && (!checkOwned || om.isOwner()))
                .map(OrganisationMember::getOrganisation)
                .findFirst().orElseThrow(NotOwnerException::new);
    }

    @Override
    public Organisation addUserToOrganisation(User owner, String email, UUID orgId) throws NotOwnerException, NotFoundException {
        return organisationMemberDao.addUserToOrganisation(
                userDao.readUser(email).orElseThrow(NotFoundException::new),
                getOwnedOrganisation(owner, orgId, true),
                false);
    }

    @Override
    public Organisation removeUserFromOrganisation(User owner, UUID removedUserId, UUID orgId) throws NotOwnerException, NotFoundException {
        return organisationMemberDao.removeUserFromOrganisation(
                userDao.readUser(removedUserId).orElseThrow(NotFoundException::new),
                getOwnedOrganisation(owner, orgId, true));
    }

    @Override
    public Role createRole(String name, UUID orgId, Set<Permission> permissions) throws AlreadyExistsException, NotFoundException {
        Organisation organisation = organisationDao.readOrganisation(orgId).orElseThrow(NotFoundException::new);
        if (organisation.getRoles().stream().anyMatch(r -> r.getName().equals(name))) {
            throw new AlreadyExistsException();
        } else {
            return roleDao.createRole(new Role(name).addOrganisation(organisation), permissions);
        }
    }

    @Override
    public User addRoleToUser(User owner, UUID orgId, UUID targetUserId, UUID roleId) throws NotFoundException, NotOwnerException {
        Organisation organisation = getOwnedOrganisation(owner, orgId, true);
        User user = userDao.readUser(targetUserId).orElseThrow(NotFoundException::new);
        Role role = organisation.getRoles().stream().filter(r -> r.is(roleId)).findFirst().orElseThrow(NotFoundException::new);
        if (user.getOrganisations().stream().anyMatch(om -> om.getOrganisation().is(orgId))) {
            roleDao.addRoleToUser(user, role);
            return user;
        } else {
            throw new NotFoundException(); // user is not in the same organisation as owner
        }
    }

    @Override
    public User removeRoleFromUser(User owner, UUID orgId, UUID targetUserId, UUID roleId) throws NotOwnerException, NotFoundException {
        Organisation organisation = getOwnedOrganisation(owner, orgId, true);
        User user = userDao.readUser(targetUserId).orElseThrow(NotFoundException::new);
        if (user.getOrganisations().stream().anyMatch(om -> om.getOrganisation().is(orgId))) {
            roleDao.removeRoleFromUser(user, roleDao.readRole(roleId).orElseThrow(NotFoundException::new));
            return user;
        } else {
            throw new NotFoundException(); // user is not in the same organisation as owner
        }
    }

    @Override
    public Group createGroup(String name, UUID orgId) {
        // TODO
        return null;
    }

    @Override
    public User addUserToGroup(User owner, UUID targetUserId, UUID groupId) {
        // TODO
        return null;
    }

    @Override
    public User removeUserFromGroup(User owner, UUID targetUserId, UUID groupId) {
        // TODO
        return null;
    }

    @Override
    public Group addRoleToGroup(User owner, UUID roleId, UUID groupId) {
        // TODO
        return null;
    }

    @Override
    public Group removeRoleFromGroup(User owner, UUID roleId, UUID groupId) {
        // TODO
        return null;
    }

    @Override
    public List<Permission> listPermissions(User owner, UUID targetUserId) {
        // TODO
        return null;
    }

    @Override
    public Permission createPermission(String permission) {
        // TODO
        return null;
    }

    @Override
    public User addPermissionToUser(UUID userId, UUID permissionId) {
        // TODO
        return null;
    }

    @Override
    public User removePermissionFromUser(UUID userId, UUID permissionId) {
        // TODO
        return null;
    }
}
