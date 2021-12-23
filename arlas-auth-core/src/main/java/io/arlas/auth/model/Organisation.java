package io.arlas.auth.model;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "organisation")
public class Organisation {
    public static final String nameColumn = "name";

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column(name = nameColumn, unique = true)
    private String name;

    @OneToMany(mappedBy = "pk.organisation")
    private Set<OrganisationMember> members = new HashSet<>();

    @OneToMany(mappedBy="key.organisation")
    private Set<Group> groups = new HashSet<>();

    @ManyToMany(mappedBy="organisations")
    private Set<Role> roles = new HashSet<>();

    private Organisation() {}

    public Organisation(String name) {
        this.name = name;
    }

    public UUID getId() {
        return id;
    }

    public boolean is(UUID uuid) {
        return this.id.equals(uuid);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<OrganisationMember> getMembers() {
        return members;
    }

    public void setMembers(Set<OrganisationMember> members) {
        this.members = members;
    }

    public boolean addMember(OrganisationMember organisationMember) {
        return this.members.add(organisationMember);
    }

    public boolean removeMember(OrganisationMember organisationMember) {
        return this.members.remove(organisationMember);
    }

    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
