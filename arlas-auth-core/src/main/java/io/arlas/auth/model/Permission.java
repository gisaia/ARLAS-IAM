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

}
