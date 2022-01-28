package io.arlas.auth.core;

import io.arlas.auth.model.TokenSecret;

import java.util.Optional;

public interface TokenSecretDao {

    TokenSecret createSecret(TokenSecret secret);
    Optional<TokenSecret> readSecret();
}
