package io.arlas.ums.rest.model.output;

import io.arlas.ums.model.Role;

import java.util.UUID;

public class RoleData {
    public UUID id;
    public String name;
    public String description;
    public boolean isSystem;

    public RoleData(Role r) {
        this.id = r.getId();
        this.name = r.getName();
        this.description = r.getDescription();
        this.isSystem = r.isSystem();
    }
}
