package io.arlas.ums.model;

public class LoginSession {
    public String accessToken; // JWT
    public RefreshToken refreshToken;

    public LoginSession(){}

    public LoginSession(User subject, String accessToken, String refreshToken, long refreshTokenExpiryDate) {
        this.accessToken = accessToken;
        this.refreshToken = new RefreshToken(subject.getId(), refreshToken, refreshTokenExpiryDate);
    }
}
