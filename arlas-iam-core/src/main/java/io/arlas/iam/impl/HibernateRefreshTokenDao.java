package io.arlas.iam.impl;

import io.arlas.iam.core.RefreshTokenDao;
import io.arlas.iam.model.RefreshToken;
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
    public void createOrUpdate(UUID userId, RefreshToken token) {
        read(userId).ifPresent(this::delete);
        persist(token);
    }

    @Override
    public void delete(RefreshToken token) {
        currentSession().remove(token);
        currentSession().flush();
    }
}
