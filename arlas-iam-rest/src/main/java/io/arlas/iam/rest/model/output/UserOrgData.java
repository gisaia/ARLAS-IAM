package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;

import java.util.UUID;

public class UserOrgData implements Comparable {
    public UUID id;
    public String name;
    public String displayName;
    public boolean isOwner;

    public UserOrgData(Organisation o, User u) {
        this.id = o.getId();
        this.name = o.getName();
        this.displayName = o.getDisplayName();
        this.isOwner = o.getMembers().stream()
                .filter(m -> m.getUser().is(u.getId()))
                .map(OrganisationMember::isOwner)
                .findFirst()
                .orElse(false);
    }

    @Override
    public int compareTo(Object o) {
        return name.compareTo(((UserOrgData) o).name);
    }
}
