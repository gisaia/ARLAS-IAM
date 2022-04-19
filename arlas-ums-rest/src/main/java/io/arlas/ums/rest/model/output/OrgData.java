package io.arlas.ums.rest.model.output;

import io.arlas.ums.model.Organisation;

import java.util.List;
import java.util.UUID;

public class OrgData {
    public UUID id;
    public String name;
    public List<MemberData> members;

    public OrgData(Organisation o) {
        this.id = o.getId();
        this.name = o.getName();
        this.members = o.getMembers().stream().map(MemberData::new).toList();
    }
}
