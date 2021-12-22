package io.arlas.auth.model;

import org.hibernate.annotations.Type;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "permission")
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Integer id;

    @NotNull
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

    public Integer getId() {
        return id;
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

    public void setSystem(boolean system) {
        isSystem = system;
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
}
