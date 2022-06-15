package io.arlas.iam.impl;

import io.arlas.iam.model.TokenSecret;
import io.arlas.iam.core.TokenSecretDao;
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