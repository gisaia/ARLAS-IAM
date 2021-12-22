package io.arlas.auth.core;

import io.arlas.auth.model.*;

public interface OrganisationMemberDao {

    Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner);

    Organisation removeUserFromOrganisation(User user, Organisation organisation);

}
