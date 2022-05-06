package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.OrganisationMember;

public class MemberData {
    public UserData member;
    public boolean isOwner;

    public MemberData(OrganisationMember om) {
        this.member = new UserData(om.getUser());
        this.isOwner = om.isOwner();
    }
}
