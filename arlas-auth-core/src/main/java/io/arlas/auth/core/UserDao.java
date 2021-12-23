package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.User;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface UserDao {

    User createUser(User user);

    Optional<User> readUser(UUID userId);

    Optional<User> readUser(String email);

    User updateUser(User user);

    User deleteUser(User user);

    User activateUser(UUID userId);

    User deactivateUser(UUID userId);

    User verifyUser(UUID userId);

    Set<Organisation> listOrganisations(User user);

    Set<Permission> listPermissions(User user);

    User addPermissionToUser(User user, Permission permission);

    User removePermissionFromUser(User user, Permission permission);

}
