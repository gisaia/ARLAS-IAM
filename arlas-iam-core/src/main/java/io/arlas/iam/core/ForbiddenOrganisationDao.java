package io.arlas.iam.core;

import io.arlas.iam.model.ForbiddenOrganisation;

import java.util.List;
import java.util.Optional;

public interface ForbiddenOrganisationDao {

    Optional<ForbiddenOrganisation> getName(String name);
    ForbiddenOrganisation addName(ForbiddenOrganisation name);

    List<ForbiddenOrganisation> listNames();

    void removeName(ForbiddenOrganisation name);
}
