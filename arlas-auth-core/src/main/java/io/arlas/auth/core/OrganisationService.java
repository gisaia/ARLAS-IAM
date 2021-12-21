package io.arlas.auth.core;

import io.arlas.auth.model.*;

import java.util.List;
import java.util.Set;

public interface OrganisationService {

    Organisation createOrganisation(Organisation organisation);

    Organisation deleteOrganisation(Organisation organisation);


    Set<User> listUsers(User user); // list users from the same organisations as the requesting user

}
