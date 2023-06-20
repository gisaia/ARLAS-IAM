package io.arlas.iam.impl;

import io.arlas.iam.core.ApiKeyDao;
import io.arlas.iam.model.ApiKey;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.UUID;

public class HibernateApiKeyDao extends AbstractDAO<ApiKey> implements ApiKeyDao {

    public HibernateApiKeyDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public ApiKey createApiKey(ApiKey apiKey) {
        return persist(apiKey);
    }

    @Override
    public Optional<ApiKey> readApiKey(UUID id) {
        return Optional.ofNullable(get(id));
    }

    @Override
    public Optional<ApiKey> readApiKey(String keyId) {
        return currentSession().byNaturalId(ApiKey.class).using("keyId", keyId).loadOptional();
    }

    @Override
    public void deleteApiKey(ApiKey apiKey) {
        currentSession().delete(apiKey);
    }
}
