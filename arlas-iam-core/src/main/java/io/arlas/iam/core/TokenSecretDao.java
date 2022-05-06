package io.arlas.iam.core;

import io.arlas.iam.model.TokenSecret;

import java.util.Optional;

public interface TokenSecretDao {

    TokenSecret createSecret(TokenSecret secret);
    Optional<TokenSecret> readSecret();
}
