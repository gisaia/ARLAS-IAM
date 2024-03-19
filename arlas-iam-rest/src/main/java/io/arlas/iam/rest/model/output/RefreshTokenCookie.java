package io.arlas.iam.rest.model.output;

import io.arlas.iam.exceptions.InvalidTokenException;
import io.arlas.iam.model.RefreshToken;

public class RefreshTokenCookie {
    public String userId;
    public String refreshToken;

    public RefreshTokenCookie(RefreshToken rt) {
        this.userId = rt.getUserId().toString();
        this.refreshToken = rt.getValue();
    }

    public RefreshTokenCookie(String cookieValue) throws InvalidTokenException {
        String[] v = parseCookieValue(cookieValue);
        this.userId = v[0];
        this.refreshToken = v[1];
    }


    public String getCookieValue() {
        return String.join("/", this.userId, this.refreshToken);
    }

    public String[] parseCookieValue(String cookieValue) throws InvalidTokenException {
        if (cookieValue.contains("/")) {
            return cookieValue.split("/");
        } else {
            throw new InvalidTokenException("Refresh Token format invalid.");
        }
    }
}
