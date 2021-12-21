package io.arlas.auth.model;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "group")
public class Group {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Integer id;

    @EmbeddedId
    private GroupKey key;

    @ManyToMany()
    @JoinTable(name = "GroupMember",
            joinColumns = @JoinColumn(name = "id_group"),
            inverseJoinColumns = @JoinColumn(name = "id_user"))
    private Set<User> members = new HashSet<>();

    private Group() {}

    public Integer getId() {
        return id;
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
}