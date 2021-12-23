package io.arlas.auth.model;

import javax.persistence.Embeddable;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import java.io.Serial;
import java.util.Objects;

@Embeddable
public class OrganisationMemberPk implements java.io.Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @ManyToOne
    @JoinColumn(name = "id_user")
    private User user;

    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation org;

    private OrganisationMemberPk() {}

    public OrganisationMemberPk(User user, Organisation organisation) {
        this.user = user;
        this.org = organisation;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User u) {
        this.user = u;
    }

    public Organisation getOrganisation() {
        return org;
    }

    public void setOrganisation(Organisation o) {
        this.org = o;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OrganisationMemberPk that = (OrganisationMemberPk) o;
        return getUser().equals(that.getUser()) && org.equals(that.org);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUser(), org);
    }
}