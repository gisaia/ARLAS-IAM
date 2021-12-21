package io.arlas.auth.model;

import org.hibernate.annotations.Type;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class OrganisationMember {

    @Id
    private OrganisationMemberPk pk;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_owner")
    private boolean isOwner;

    private OrganisationMember() {}

    public OrganisationMemberPk getPk() {
        return pk;
    }

    public void setPk(OrganisationMemberPk pk) {
        this.pk = pk;
    }

    public boolean isOwner() {
        return isOwner;
    }

    public void setOwner(boolean isOwner) {
        this.isOwner = isOwner;
    }

    public User getUser() {
        return pk.getUser();
    }

    public void setUser(User user) {
        getPk().setUser(user);
    }

    public Organisation getOrganisation() {
        return pk.getOrganisation();
    }

    public void setOrganisation(Organisation organisation) {
        getPk().setOrganisation(organisation);
    }
}