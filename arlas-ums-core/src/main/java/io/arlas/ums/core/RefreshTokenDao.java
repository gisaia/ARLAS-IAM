package io.arlas.ums.core;

import io.arlas.ums.model.RefreshToken;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenDao {

    Optional<RefreshToken> read(UUID userId);

    Optional<RefreshToken> read(String value);

    void createOrUpdate(UUID userId, RefreshToken token);

    void delete(RefreshToken token);
}
