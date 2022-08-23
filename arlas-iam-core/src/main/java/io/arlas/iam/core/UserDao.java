package io.arlas.iam.core;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.User;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface UserDao {

    List<User> listUsers();

    List<User> listUsers(String domain);

    User createUser(User user);

    Optional<User> readUser(UUID userId);

    Optional<User> readUser(String email);

    User updateUser(User user);

    User deleteUser(User user);

    User activateUser(UUID userId);

    User deactivateUser(UUID userId);

    Set<Organisation> listOrganisations(User user);
}
