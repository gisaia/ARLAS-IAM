package io.arlas.auth.model;


public class LoginSession {
    public String accessToken; // JWT
    public String refreshToken; // opaque string
    public long refreshTokenExpiryDate;

    public LoginSession(){};

    public LoginSession(String accessToken, String refreshToken, long refreshTokenExpiryDate) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.refreshTokenExpiryDate = refreshTokenExpiryDate;
    }
}
