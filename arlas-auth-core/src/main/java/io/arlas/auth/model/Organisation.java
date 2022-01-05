package io.arlas.auth.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "organisation")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Organisation {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NaturalId
    @Column
    private String name;

    @OneToMany(mappedBy = "pk.org", fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
    private Set<OrganisationMember> members = new HashSet<>();

    @OneToMany(mappedBy="organisation", fetch = FetchType.EAGER)
    private Set<Group> groups = new HashSet<>();

    @ManyToMany(mappedBy="organisations", fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();

    private Organisation() {}

    public Organisation(String name) {
        this.name = name;
    }

    public UUID getId() {
        return id;
    }

    private void setId(UUID id) {
        this.id = id;
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

    public void addGroup(Group group) {
        this.groups.add(group);
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void addRole(Role role) {
        this.roles.add(role);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Organisation that = (Organisation) o;
        return getId().equals(that.getId()) && getName().equals(that.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getName());
    }

}
