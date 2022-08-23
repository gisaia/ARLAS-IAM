package io.arlas.iam.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.*;

@Entity
@Table(name = "role")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Role {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column
    private String name;

    @Column
    private String description;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_system")
    private boolean isSystem = false; // system roles are shared among all organisations

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_technical")
    private boolean isTechnical = false; // technical roles

    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation organisation;

    @ManyToMany()
    @JoinTable(name = "UserRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> users = new HashSet<>();

    @ManyToMany(mappedBy="roles", cascade= CascadeType.REMOVE)
    private Set<Permission> permissions = new HashSet<>();

    private Role() {}

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public Role(String name, String description, boolean isTechnical) {
        this(name, description);
        this.isTechnical = isTechnical;
    }

    public Role(String name, boolean isSystem) {
        this.name = name;
        this.isSystem = isSystem;
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

    public Role setName(String name) {
        this.name = name;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public Role setDescription(String description) {
        this.description = description;
        return this;
    }

    public boolean isSystem() {
        return isSystem;
    }

    public void setSystem(boolean isSystem) {
        this.isSystem = isSystem;
    }

    public boolean isTechnical() {
        return isTechnical;
    }

    public void setTechnical(boolean technical) {
        isTechnical = technical;
    }

    public Optional<Organisation> getOrganisation() {
        return Optional.ofNullable(organisation);
    }

    public Role setOrganisation(Organisation organisation) {
        this.organisation = organisation;
        organisation.getRoles().add(this);
        return this;
    }

    public Set<User> getUsers() {
        return users;
    }

    public Role setUsers(Set<User> users) {
        this.users = users;
        return this;
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
        return getName().equals(role.getName()) && Objects.equals(getOrganisation(), role.getOrganisation());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getOrganisation());
    }

    @Override
    public String toString() {
        return "Role{" +
                "name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", permissions=" + permissions +
                '}';
    }
}
