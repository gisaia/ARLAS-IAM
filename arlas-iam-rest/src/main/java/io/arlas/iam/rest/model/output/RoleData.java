package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Role;

import java.util.UUID;

public class RoleData implements Comparable<RoleData> {
    public UUID id;
    public String name;

    public String fullName;
    public String description;
    public OrgData organisation;

    public boolean isGroup;
    public boolean isTechnical;

    public RoleData(Role r) {
        this.id = r.getId();
        this.isGroup = r.isGroup();
        this.name = isGroup ? r.getName().substring(r.getName().lastIndexOf("/")+1) : r.getName();
        this.fullName = r.getName();
        this.description = r.getDescription();
        this.isTechnical = r.isTechnical();
        if (r.getOrganisation().isPresent()) {
            this.organisation = new OrgData(r.getOrganisation().get(), false);
        }
    }

    @Override
    public int compareTo(RoleData o) {
        return name.compareTo(o.name);
    }
}
