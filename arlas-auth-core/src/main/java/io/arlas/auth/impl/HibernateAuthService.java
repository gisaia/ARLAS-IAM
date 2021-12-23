package io.arlas.auth.impl;

import io.arlas.auth.core.*;
import io.arlas.auth.exceptions.*;
import io.arlas.auth.model.*;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;
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

    @Override
    public User createUser(String email) throws InvalidEmailException, AlreadyExistsException {
        Matcher regexMatcher = emailRegex.matcher(email);
        if (regexMatcher.find()) {
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
    public Optional<User> readUser(Integer userId) {
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
    public Optional<User> deleteUser(Integer userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> userDao.deleteUser(u));
        return user;
    }

    @Override
    public Optional<User> activateUser(Integer userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setActive(true);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public Optional<User> verifyUser(Integer userId, String password) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setPassword(encode(password));
            u.setVerified(true);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public Optional<User> deactivateUser(Integer userId) {
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
    public Organisation createOrganisation(User owner, String name) throws AlreadyExistsException, ForbiddenOrganisationNameException {
        Matcher regexMatcher = emailRegex.matcher(owner.getEmail());
        if (regexMatcher.find()) {
            String domain = regexMatcher.group();
            if (organisationDao.readOrganisation(name).isPresent()) {
                throw new AlreadyExistsException();
            } if (!domain.equals(name)) { // user can only create his domain as organisation name
                throw new ForbiddenOrganisationNameException();
            }
            else {
                Organisation organisation = organisationDao.createOrganisation(new Organisation(domain));
                organisationMemberDao.addUserToOrganisation(owner, organisation, true);
                return organisation;
            }
        } else {
            // should not happen as we checked when he was created
            throw new RuntimeException("Invalid owner email address for userId: " + owner.getId());
        }
    }

    @Override
    public Optional<Organisation> deleteOrganisation(User user, Integer orgId) {
        Optional<Organisation> organisation = organisationDao.readOrganisation(orgId);
        organisation.ifPresent(o -> organisationDao.deleteOrganisation(o));
        // TODO : delete associated resources
        return organisation;
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    private Optional<Organisation> getOwnedOrganisation(User owner, Integer orgId, boolean checkOwned) {
        return owner.getOrganisations().stream()
                .filter(om -> (om.getOrganisation().getId() == orgId) && (!checkOwned || om.isOwner()))
                .map(o -> o.getOrganisation())
                .findFirst();
    }

    @Override
    public Organisation addUserToOrganisation(User owner, String email, Integer orgId) throws NotOwnerException, AlreadyExistsException, InvalidEmailException {
        Optional<Organisation> organisation = getOwnedOrganisation(owner, orgId, true);
        User newUser = userDao.readUser(email).orElse(createUser(email));
        organisation.ifPresent(
                o -> organisationMemberDao.addUserToOrganisation(newUser, o, false)
        );
        return organisation.orElseThrow(() -> new NotOwnerException());
    }

    @Override
    public Organisation removeUserFromOrganisation(User owner, String removedUserId, Integer orgId) throws NotOwnerException {
        Optional<Organisation> organisation = getOwnedOrganisation(owner, orgId, true);
        organisation.ifPresent(
                o -> userDao.readUser(removedUserId).ifPresent(u -> organisationMemberDao.removeUserFromOrganisation(u, o))
        );
        return organisation.orElseThrow(() -> new NotOwnerException());
    }

    @Override
    public Role createRole(String name, Integer orgId, List<Permission> permissions) {
        // TODO
        return null;
    }

    @Override
    public User addRoleToUser(String actingUserId, String targetUserId, String roleId) {
        // TODO
        return null;
    }

    @Override
    public User removeRoleFromUser(String actingUserId, String targetUserId, String roleId) {
        // TODO
        return null;
    }

    @Override
    public Group createGroup(String name, Integer orgId) {
        // TODO
        return null;
    }

    @Override
    public User addUserToGroup(String actingUserId, String targetUserId, String groupId) {
        // TODO
        return null;
    }

    @Override
    public User removeUserFromGroup(String actingUserId, String targetUserId, String groupId) {
        // TODO
        return null;
    }

    @Override
    public Group addRoleToGroup(String actingUserId, String roleId, String groupId) {
        // TODO
        return null;
    }

    @Override
    public Group removeRoleFromGroup(String actingUserId, String roleId, String groupId) {
        // TODO
        return null;
    }

    @Override
    public List<Permission> listPermissions(String actingUserId, String targetUserId) {
        // TODO
        return null;
    }

    @Override
    public Permission createPermission(String permission) {
        // TODO
        return null;
    }

    @Override
    public User addPermissionToUser(Integer userId, String permissionId) {
        // TODO
        return null;
    }

    @Override
    public User removePermissionFromUser(Integer userId, String permissionId) {
        // TODO
        return null;
    }
}
