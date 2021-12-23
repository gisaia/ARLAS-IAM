package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.User;

import java.util.Optional;
import java.util.Set;

public interface UserDao {

    User createUser(User user);

    Optional<User> readUser(Integer userId);

    Optional<User> readUser(String email);

    User updateUser(User user);

    User deleteUser(User user);

    User activateUser(Integer userId);

    User deactivateUser(Integer userId);

    User verifyUser(Integer userId);

    Set<Organisation> listOrganisations(User user);

    Set<Permission> listPermissions(User user);

    User addPermissionToUser(User user, Permission permission);

    User removePermissionFromUser(User user, Permission permission);

}
