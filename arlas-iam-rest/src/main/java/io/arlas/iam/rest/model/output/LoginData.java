package io.arlas.iam.rest.model.output;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.iam.model.LoginSession;

public class LoginData {
    @JsonProperty("access_token")
    public String accessToken; // JWT
    public UserData user;

    public LoginData(LoginSession loginSession) {
        this.accessToken = loginSession.accessToken;
        this.user = new UserData(loginSession.user, true);
    }
}
