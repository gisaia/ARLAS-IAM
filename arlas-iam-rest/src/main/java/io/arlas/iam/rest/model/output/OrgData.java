package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;

import java.util.List;
import java.util.UUID;

public class OrgData implements Comparable {
    public UUID id;
    public String name;
    public String displayName;
    public List<MemberData> members;

    public OrgData(Organisation o) {
        this(o, true);
    }

    public OrgData(Organisation o, boolean withMembers) {
        this.id = o.getId();
        this.name = o.getName();
        this.displayName = o.getDisplayName();
        if (withMembers) {
            this.members = o.getMembers().stream().filter(om -> !om.isAdmin()).map(MemberData::new).toList();
        }
    }

    @Override
    public int compareTo(Object o) {
        return name.compareTo(((OrgData) o).name);
    }

}
