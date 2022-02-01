package io.arlas.auth.impl;

import io.arlas.auth.core.RefreshTokenDao;
import io.arlas.auth.model.RefreshToken;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.UUID;

public class HibernateRefreshTokenDao extends AbstractDAO<RefreshToken> implements RefreshTokenDao {
    public HibernateRefreshTokenDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Optional<RefreshToken> read(UUID userId) {
        return Optional.ofNullable(get(userId));
    }

    @Override
    public Optional<RefreshToken> read(String value) {
        return currentSession().byNaturalId(RefreshToken.class).using("value", value).loadOptional();
    }

    @Override
    public void createOrUpdate(RefreshToken token) {
        persist(token);
    }

    @Override
    public void delete(RefreshToken token) {
        currentSession().delete(token);
        currentSession().flush();
    }
}
