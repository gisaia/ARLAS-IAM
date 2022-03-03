package io.arlas.ums.core;

import io.arlas.ums.model.TokenSecret;

import java.util.Optional;

public interface TokenSecretDao {

    TokenSecret createSecret(TokenSecret secret);
    Optional<TokenSecret> readSecret();
}
