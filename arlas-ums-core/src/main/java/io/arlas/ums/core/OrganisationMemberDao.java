package io.arlas.ums.core;

import io.arlas.ums.model.Organisation;
import io.arlas.ums.model.User;

public interface OrganisationMemberDao {

    Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner);

    Organisation removeUserFromOrganisation(User user, Organisation organisation);

}
