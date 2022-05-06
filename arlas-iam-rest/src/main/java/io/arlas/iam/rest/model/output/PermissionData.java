package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Permission;

import java.util.List;
import java.util.UUID;

public class PermissionData {
    public UUID id;
    public String value;
    public String description;
    public List<RoleData> roles;

    public PermissionData(Permission p) {
        this.id = p.getId();
        this.value = p.getValue();
        this.description = p.getDescription();
        this.roles = p.getRoles().stream().map(RoleData::new).toList();
    }
}
