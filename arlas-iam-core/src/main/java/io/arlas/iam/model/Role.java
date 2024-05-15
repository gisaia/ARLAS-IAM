package io.arlas.iam.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.arlas.filter.config.TechnicalRoles;
import io.dropwizard.jackson.JsonSnakeCase;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.util.*;

@Entity
@Table(name = "role")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Role {
    private static final String GROUP_PREFIX = TechnicalRoles.getDefaultGroup("");

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column
    private String name;

    @Column
    private String description;

    @Basic
    @Convert(converter = org.hibernate.type.NumericBooleanConverter.class)
    @Column(name="is_system")
    private boolean isSystem = false; // system roles are shared among all organisations

    @Basic
    @Convert(converter = org.hibernate.type.NumericBooleanConverter.class)
    @Column(name="is_technical")
    private boolean isTechnical = false; // technical roles

    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation organisation;

    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "UserRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> users = new HashSet<>();

    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "ApiKeyRole",
            joinColumns = @JoinColumn(name = "id_role"),
            inverseJoinColumns = @JoinColumn(name = "id_apikey"))
    private Set<ApiKey> apiKeys = new HashSet<>();

    @ManyToMany(mappedBy="roles")
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

    @PreRemove
    private void removePermissionAssociations() {
        for (Permission permission : this.permissions) {
            permission.getRoles().remove(this);
        }
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

    public boolean isGroup() { return name.startsWith(GROUP_PREFIX); }

    public boolean isSystem() {
        return isSystem;
    }

    public void setSystem(boolean isSystem) {
        this.isSystem = isSystem;
    }

    public boolean isTechnical() {
        return isTechnical;
    }

    public Role setTechnical(boolean technical) {
        isTechnical = technical;
        return this;
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

    public void removeUser(User user) {
        this.users.remove(user);
        user.getRoles().remove(this);
    }

    public void addUser(User user) {
        this.users.add(user);
        user.getRoles().add(this);
    }

    public Set<ApiKey> getApiKeys() {
        return apiKeys;
    }

    public void setApiKeys(Set<ApiKey> apiKeys) {
        this.apiKeys = apiKeys;
    }

    public void removeApiKey(ApiKey apiKey) {
        this.apiKeys.remove(apiKey);
        apiKey.getRoles().remove(this);
    }

    public void addApiKeys(ApiKey apiKey) {
        this.apiKeys.add(apiKey);
        apiKey.getRoles().add(this);
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
