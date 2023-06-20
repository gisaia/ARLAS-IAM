package io.arlas.iam.core;

import io.arlas.iam.model.ApiKey;

import java.util.Optional;
import java.util.UUID;

public interface ApiKeyDao {

    ApiKey createApiKey(ApiKey apiKey);
    Optional<ApiKey> readApiKey(UUID apiKeyId);
    Optional<ApiKey> readApiKey(String keyId);
    void deleteApiKey(ApiKey apiKey);

}
