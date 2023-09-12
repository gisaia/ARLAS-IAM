package io.arlas.iam.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.Type;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "organisationMember")
@JsonSnakeCase
public class OrganisationMember {

    @Id
    @JsonIgnore
    private OrganisationMemberPk pk;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_owner")
    private boolean isOwner;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_admin")
    private boolean isAdmin;

    private OrganisationMember() {}

    public OrganisationMember(User user, Organisation organisation, boolean isOwner) {
        this(user, organisation, isOwner, false);
    }

    public OrganisationMember(User user, Organisation organisation, boolean isOwner, boolean isAdmin) {
        this.pk = new OrganisationMemberPk(user, organisation);
        this.isOwner = isOwner;
        this.isAdmin = isAdmin;
    }

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

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean admin) {
        isAdmin = admin;
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