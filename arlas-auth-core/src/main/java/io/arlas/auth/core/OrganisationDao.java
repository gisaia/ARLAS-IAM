package io.arlas.auth.core;

import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;

import java.util.Set;

public interface OrganisationDao {

    Organisation createOrganisation(Organisation organisation);

    Organisation deleteOrganisation(Organisation organisation);

    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

}
