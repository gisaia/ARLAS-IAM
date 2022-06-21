package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.LoginSession;
import io.arlas.iam.model.RefreshToken;

public class LoginData {
    public String accessToken; // JWT
    public RefreshToken refreshToken;
    public UserData user;

    public LoginData(LoginSession loginSession) {
        this.accessToken = loginSession.accessToken;
        this.refreshToken = loginSession.refreshToken;
        this.user = new UserData(loginSession.user, true);
    }
}
