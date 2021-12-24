package io.arlas.auth.model;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "groups", uniqueConstraints = { @UniqueConstraint(columnNames = { "name", "id_organisation" }) })
public class Group {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column
    private String name;

    @NotNull
    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation organisation;

    @ManyToMany()
    @JoinTable(name = "GroupMember",
            joinColumns = @JoinColumn(name = "id_group"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> members = new HashSet<>();

    @ManyToMany(mappedBy="groups")
    private Set<Role> roles = new HashSet<>();

    private Group() {}

    public Group(String name, Organisation organisation) {
        this.name = name;
        this.organisation = organisation;
    }

    private void setId(UUID id) {
        this.id = id;
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

    public Organisation getOrganisation() {
        return organisation;
    }

    public void setOrganisation(Organisation organisation) {
        this.organisation = organisation;
    }

    public Set<User> getMembers() {
        return members;
    }

    public void setMembers(Set<User> members) {
        this.members = members;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
