package io.arlas.auth.model;

import java.util.UUID;

public class LoginSession {
    public String accessToken; // JWT
    public RefreshToken refreshToken;

    public LoginSession(){}

    public LoginSession(UUID subject, String accessToken, String refreshToken, long refreshTokenExpiryDate) {
        this.accessToken = accessToken;
        this.refreshToken = new RefreshToken(subject, refreshToken, refreshTokenExpiryDate);
    }
}
