package io.arlas.auth.core;

import io.arlas.auth.model.RefreshToken;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenDao {

    Optional<RefreshToken> read(UUID userId);

    Optional<RefreshToken> read(String value);

    void createOrUpdate(UUID userId, RefreshToken token);

    void delete(RefreshToken token);
}
