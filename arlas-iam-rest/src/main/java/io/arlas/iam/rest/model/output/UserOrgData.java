package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.User;

import java.util.List;
import java.util.UUID;

public class UserOrgData {
    public UUID id;
    public String name;
    public boolean isOwner;

    public UserOrgData(Organisation o, User u) {
        this.id = o.getId();
        this.name = o.getName();
        this.isOwner = o.getMembers().stream()
                .filter(m -> m.getUser().is(u.getId()))
                .map(m -> m.isOwner())
                .findFirst()
                .orElse(false);
    }
}
