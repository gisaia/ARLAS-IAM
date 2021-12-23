package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;

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
