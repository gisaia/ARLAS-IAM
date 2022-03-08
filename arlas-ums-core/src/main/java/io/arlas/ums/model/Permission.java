package io.arlas.ums.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "permission")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Permission {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @NaturalId
    @Column(unique = true)
    private String value;

    @Type(type = "org.hibernate.type.NumericBooleanType")
    @Column(name="is_system")
    private boolean isSystem = false; // system permissions are shared among all organisations

    @ManyToMany()
    @JoinTable(name = "RolePermission",
            joinColumns = @JoinColumn(name = "id_permission"),
            inverseJoinColumns = @JoinColumn(name = "id_role"))
    private Set<Role> roles = new HashSet<>();

    @ManyToMany()
    @JoinTable(name = "UserPermission",
            joinColumns = @JoinColumn(name = "id_permission"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> users = new HashSet<>();


    private Permission() {}

    public Permission(String value, boolean isSystem) {
        this.value = value;
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

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean isSystem() {
        return isSystem;
    }

    public void setSystem(boolean isSystem) {
        this.isSystem = isSystem;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return getValue().equals(that.getValue());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getValue());
    }
}