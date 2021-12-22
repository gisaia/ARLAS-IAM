package io.arlas.auth.impl;

import io.arlas.auth.core.*;
import io.arlas.auth.exceptions.AlreadyExistsException;
import io.arlas.auth.exceptions.InvalidEmailException;
import io.arlas.auth.exceptions.NonMatchingPasswordException;
import io.arlas.auth.exceptions.NotFoundException;
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
            if (userDao.readUserByEmail(email).isEmpty()) {
                User user = new User();
                user.setEmail(email);
                // TODO add more attributes
                return userDao.createUser(user);
            } else {
                throw new AlreadyExistsException();
            }
        } else {
            throw new InvalidEmailException();
        }
    }

    @Override
    public Optional<User> readUser(String userId) {
        return userDao.readUserById(userId);
    }

    @Override
    public User login(String email, String password) throws NotFoundException {
        Optional<User> user = userDao.readUserByEmail(email);
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
    public Optional<User> deleteUser(String userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> userDao.deleteUser(u));
        return user;
    }

    @Override
    public Optional<User> activateUser(String userId) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setActive(true);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public Optional<User> verifyUser(String userId, String password) {
        Optional<User> user = readUser(userId);
        user.ifPresent(u -> {
            u.setPassword(encode(password));
            u.setVerified(true);
            userDao.updateUser(u);
        });
        return user;
    }

    @Override
    public Optional<User> deactivateUser(String userId) {
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
    public Organisation createOrganisation(User owner, String name) throws AlreadyExistsException {
        Matcher regexMatcher = emailRegex.matcher(owner.getEmail());
        if (regexMatcher.find()) {
            String domain = regexMatcher.group();
            if (organisationDao.readOrganisationByName(name).isPresent()) {
                throw new AlreadyExistsException();
            } else {
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
    public Optional<Organisation> deleteOrganisation(User user, String orgId) {
        Optional<Organisation> organisation = organisationDao.readOrganisationById(orgId);
        organisation.ifPresent(o -> organisationDao.deleteOrganisation(o));
        // TODO : delete associated resources
        return organisation;
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return userDao.listOrganisations(user);
    }

    @Override
    public User addUserToOrganisation(String actingUserId, String addedUserId, String orgId) {
        // TODO
        return null;
    }

    @Override
    public User removeUserFromOrganisation(String actingUserId, String removedUserId, String orgId) {
        // TODO
        return null;
    }

    @Override
    public Role createRole(String name, String orgId, List<Permission> permissions) {
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
    public Group createGroup(String name, String orgId) {
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
    public User addPermissionToUser(String userId, String permissionId) {
        // TODO
        return null;
    }

    @Override
    public User removePermissionFromUser(String userId, String permissionId) {
        // TODO
        return null;
    }
}
