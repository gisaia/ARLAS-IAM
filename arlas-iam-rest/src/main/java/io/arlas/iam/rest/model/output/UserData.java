package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.User;

import java.util.UUID;

public class UserData {
    public UUID id;
    public String email;

    public UserData(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
    }
}
