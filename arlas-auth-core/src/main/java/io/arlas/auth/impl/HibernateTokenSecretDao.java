package io.arlas.auth.impl;

import io.arlas.auth.core.TokenSecretDao;
import io.arlas.auth.model.TokenSecret;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;

public class HibernateTokenSecretDao extends AbstractDAO<TokenSecret> implements TokenSecretDao {
    public HibernateTokenSecretDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public TokenSecret createSecret(TokenSecret secret) {
        // we only want one secret, so we remove the previous one
        currentSession().createQuery("delete TokenSecret").executeUpdate();
        return persist(secret);
    }

    @Override
    public Optional<TokenSecret> readSecret() {
        return list(currentSession().createQuery("from TokenSecret")).stream().findFirst();
    }
}
