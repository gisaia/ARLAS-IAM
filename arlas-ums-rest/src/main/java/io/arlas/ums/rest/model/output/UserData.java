package io.arlas.ums.rest.model.output;

import io.arlas.ums.model.User;

import java.util.UUID;

public class UserData {
    public UUID id;
    public String email;

    public UserData(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
    }
}
