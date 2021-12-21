package io.arlas.auth.impl;

import io.arlas.auth.core.UserService;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

public class HibernateUserService extends AbstractDAO<User> implements UserService {
    public HibernateUserService(SessionFactory sessionFactory) {
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
    public User deleteUser(String userId) {
        // TODO: delete user resources (organisation, collections...)
        return deleteUser(userId);
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
}
