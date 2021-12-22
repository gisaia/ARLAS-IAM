package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.User;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface UserDao {

    User createUser(User user);

    Optional<User> readUserById(String userId);

    Optional<User> readUserByEmail(String email);

    User updateUser(User user);

    User deleteUser(User user);

    User activateUser(String userId);

    User deactivateUser(String userId);

    User verifyUser(String userId);

    List<Organisation> listOrganisations(User user);

    Set<Permission> listPermissions(User user);

    User addPermissionToUser(User user, Permission permission);

    User removePermissionFromUser(User user, Permission permission);

}
