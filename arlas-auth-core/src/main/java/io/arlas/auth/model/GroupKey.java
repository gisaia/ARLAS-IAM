package io.arlas.auth.model;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.validation.constraints.NotNull;
import java.util.Objects;

@Embeddable
public class GroupKey implements java.io.Serializable {

    private static final long serialVersionUID = 1L;

    @NotNull
    @Column
    private String name;

    @NotNull
    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation organisation;

    private GroupKey() {}

    public GroupKey(String name, Organisation organisation) {
        this.name = name;
        this.organisation = organisation;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Organisation getOrganisation() {
        return organisation;
    }

    public void setOrganisation(Organisation org) {
        this.organisation = org;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GroupKey groupKey = (GroupKey) o;
        return getName().equals(groupKey.getName()) && getOrganisation().equals(groupKey.getOrganisation());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getOrganisation());
    }
}
