package io.arlas.ums.core;

import io.arlas.ums.model.Organisation;
import io.arlas.ums.model.User;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface OrganisationDao {

    Organisation createOrganisation(Organisation organisation);

    Optional<Organisation> readOrganisation(UUID orgId);

    Optional<Organisation> readOrganisation(String name);

    void deleteOrganisation(Organisation organisation);

    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

}
