package io.arlas.ums.rest.model.output;

import io.arlas.ums.model.OrganisationMember;

public class MemberData {
    public UserData member;
    public boolean isOwner;

    public MemberData(OrganisationMember om) {
        this.member = new UserData(om.getUser());
        this.isOwner = om.isOwner();
    }
}
