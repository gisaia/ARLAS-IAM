package io.arlas.iam.core;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.User;

public interface OrganisationMemberDao {

    Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner);

    Organisation removeUserFromOrganisation(User user, Organisation organisation);

}
