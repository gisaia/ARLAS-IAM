package io.arlas.auth.core;

import io.arlas.auth.model.User;

import java.util.List;

public interface UserService {
    User createUser(User user);

    User readUser(String userId);

    User updateUser(User user);

    User deleteUser(String userId);

    User activateUser(String userId);

    User deactivateUser(String userId);

    User verifyUser(String userId);
}
