package io.arlas.auth.impl;

import io.arlas.auth.core.UserDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Set;
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
    public User readUser(String userId) {
        return get(userId);
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
    public User activateUser(String userId) {
        return persist(get(userId).setActive(true));
    }

    @Override
    public User deactivateUser(String userId) {
        return persist(get(userId).setActive(false));
    }

    @Override
    public User verifyUser(String userId) {
        return persist(get(userId).setVerified(true));
    }

    @Override
    public List<Organisation> listOrganisations(User user) {
        return user.getOrganisations().stream()
                .map(om -> om.getOrganisation())
                .collect(Collectors.toList());
    }

    @Override
    public Set<Permission> listPermissions(User user) {
        return user.getPermissions();
    }

    @Override
    public User addPermissionToUser(User user, Permission permission) {
        user.getPermissions().add(permission);
        return persist(user);
    }

    @Override
    public User removePermissionFromUser(User user, Permission permission) {
        user.getPermissions().remove(permission);
        return persist(user);
    }

}
