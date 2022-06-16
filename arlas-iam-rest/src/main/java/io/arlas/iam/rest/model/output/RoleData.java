package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Role;

import java.util.UUID;

public class RoleData {
    public UUID id;
    public String name;
    public String description;
    public OrgData organisation;

    public RoleData(Role r) {
        this.id = r.getId();
        this.name = r.getName();
        this.description = r.getDescription();
        if (r.getOrganisation().isPresent()) {
            this.organisation = new OrgData(r.getOrganisation().get(), false);
        }
    }
}
