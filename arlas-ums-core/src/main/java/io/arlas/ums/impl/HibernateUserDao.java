package io.arlas.ums.impl;

import io.arlas.ums.core.UserDao;
import io.arlas.ums.model.Organisation;
import io.arlas.ums.model.OrganisationMember;
import io.arlas.ums.model.Permission;
import io.arlas.ums.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class HibernateUserDao extends AbstractDAO<User> implements UserDao {
    public HibernateUserDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public User createUser(User user) {
        return persist(user);
    }

    @Override
    public Optional<User> readUser(UUID userId) {
        return Optional.ofNullable(get(userId));
    }

    @Override
    public Optional<User> readUser(String email) {
        return currentSession().byNaturalId(User.class).using("email", email).loadOptional();
    }

    @Override
    public User updateUser(User user) {
        return persist(user);
    }

    @Override
    public User deleteUser(User user) {
        // TODO: delete user resources (organisation, collections...)
        currentSession().delete(user);
        return user;
    }

    @Override
    public User activateUser(UUID userId) {
        return persist(get(userId).setActive(true));
    }

    @Override
    public User deactivateUser(UUID userId) {
        return persist(get(userId).setActive(false));
    }

    @Override
    public User verifyUser(UUID userId) {
        return persist(get(userId).setVerified(true));
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return user.getOrganisations().stream()
                .map(OrganisationMember::getOrganisation)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Permission> listPermissions(User user) {
        return user.getPermissions();
    }

    @Override
    public User addPermissionToUser(User user, Permission permission) {
        user.getPermissions().add(permission);
        permission.getUsers().add(user);
        return persist(user);
    }

    @Override
    public User removePermissionFromUser(User user, Permission permission) {
        user.getPermissions().remove(permission);
        permission.getUsers().remove(user);
        return persist(user);
    }

}
