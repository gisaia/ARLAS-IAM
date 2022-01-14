package io.arlas.auth.model;

import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "role")
@JsonSnakeCase
public class Role {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column
    private String name;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_system")
    private boolean isSystem = false; // system roles are shared among all organisations

    @ManyToMany()
    @JoinTable(name = "OrganisationRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_organisation"))
    private Set<Organisation> organisations = new HashSet<>();

    @ManyToMany()
    @JoinTable(name = "GroupRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_group"))
    private Set<Group> groups = new HashSet<>();

    @ManyToMany()
    @JoinTable(name = "UserRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> users = new HashSet<>();

    @ManyToMany(mappedBy="roles")
    private Set<Permission> permissions = new HashSet<>();

    private Role() {}

    public Role(String name) {
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

    public boolean isSystem() {
        return isSystem;
    }

    public void setSystem(boolean isSystem) {
        this.isSystem = isSystem;
    }

    public Set<Organisation> getOrganisations() {
        return organisations;
    }

    public void setOrganisations(Set<Organisation> organisations) {
        this.organisations = organisations;
    }

    public Role addOrganisation(Organisation organisation) {
        this.organisations.add(organisation);
        return this;
    }

    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return getName().equals(role.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName());
    }
}
