package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;

import java.util.List;

public interface UserDao {

    User createUser(User user);

    User readUser(String userId);

    User updateUser(User user);

    User deleteUser(User user);

    User activateUser(String userId);

    User deactivateUser(String userId);

    User verifyUser(String userId);

    List<Organisation> listOrganisations(User user);

}
