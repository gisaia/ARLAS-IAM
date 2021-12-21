package io.arlas.auth.model;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "organisation")
public class Organisation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Integer id;

    @NotNull
    @Column(unique = true)
    private String name;

    @OneToMany(mappedBy = "pk.organisation")
    private Set<OrganisationMember> members = new HashSet<>();

    @OneToMany(mappedBy="key.organisation")
    private Set<Group> groups = new HashSet<>();

    @ManyToMany(mappedBy="organisations")
    private Set<Role> roles = new HashSet<>();

    private Organisation() {}

    public Integer getId() {
        return id;
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

    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }
}
