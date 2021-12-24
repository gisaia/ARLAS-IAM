package io.arlas.auth.model;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "groups")
public class Group {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @Embedded
    private GroupKey key;

    @ManyToMany()
    @JoinTable(name = "GroupMember",
            joinColumns = @JoinColumn(name = "id_group"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> members = new HashSet<>();

    @ManyToMany(mappedBy="groups")
    private Set<Role> roles = new HashSet<>();

    private Group() {}

    public Group(String name, Organisation organisation) {
        this.key = new GroupKey(name, organisation);
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

    public GroupKey getKey() {
        return key;
    }

    public void setKey(GroupKey key) {
        this.key = key;
    }

    public String getName() {
        return key.getName();
    }

    public void setName(String name) {
        getKey().setName(name);
    }

    public Organisation getOrganisation() {
        return getKey().getOrganisation();
    }

    public void setOrganisation(Organisation organisation) {
        getKey().setOrganisation(organisation);
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
