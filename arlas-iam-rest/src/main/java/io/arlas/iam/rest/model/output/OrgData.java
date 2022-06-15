package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;

import java.util.List;
import java.util.UUID;

public class OrgData {
    public UUID id;
    public String name;
    public List<MemberData> members;

    public OrgData(Organisation o) {
        this(o, true);
    }

    public OrgData(Organisation o, boolean withMembers) {
        this.id = o.getId();
        this.name = o.getName();
        if (withMembers) {
            this.members = o.getMembers().stream().map(MemberData::new).toList();
        }
    }
}
