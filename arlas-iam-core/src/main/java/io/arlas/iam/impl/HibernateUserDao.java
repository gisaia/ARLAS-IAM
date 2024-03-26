package io.arlas.iam.impl;

import io.arlas.iam.core.UserDao;
import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class HibernateUserDao extends AbstractDAO<User> implements UserDao {
    public HibernateUserDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public List<User> listUsers() {
        return query("SELECT u FROM User u").getResultList();
    }

    @Override
    public List<User> listUsers(String domain) {
        return query("SELECT u FROM User u WHERE u.email like :email")
                .setParameter("email", "%" + (domain.startsWith("@") ? domain : "@" + domain))
                .getResultList();
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
        return persist(user.updateLastUpdate());
    }

    @Override
    public User deleteUser(User user) {
        currentSession().remove(user);
        return user;
    }

    @Override
    public User activateUser(UUID userId) {
        return persist(get(userId).setActive(true).updateLastUpdate());
    }

    @Override
    public User deactivateUser(UUID userId) {
        return persist(get(userId).setActive(false).updateLastUpdate());
    }

    @Override
    public Set<Organisation> listOrganisations(User user) {
        return user.getOrganisations().stream()
                .map(OrganisationMember::getOrganisation)
                .collect(Collectors.toSet());
    }
}
