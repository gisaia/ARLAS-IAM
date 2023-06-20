package io.arlas.iam.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "apiKey")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class ApiKey {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @Column
    private String name;

    @NaturalId
    @Column
    private String keyId;

    @Column
    private String keySecret;

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private int ttlInDays;

    @ManyToOne
    @JoinColumn(name = "id_user")
    private User owner;

    @ManyToOne
    @JoinColumn(name = "id_org")
    private Organisation org;

    @ManyToMany(mappedBy="apiKeys", cascade= CascadeType.REMOVE)
    private Set<Role> roles = new HashSet<>();

    public ApiKey() {}

    public ApiKey(String name, String keyId, String keySecret, int ttlInDays, User owner, Organisation org, Set<Role> roles) {
        this.name = name;
        this.keyId = keyId;
        this.keySecret = keySecret;
        this.ttlInDays = ttlInDays;
        this.owner = owner;
        this.org = org;
        this.roles = roles;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getKeySecret() {
        return keySecret;
    }

    public void setKeySecret(String keySecret) {
        this.keySecret = keySecret;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public int getTtlInDays() {
        return ttlInDays;
    }

    public void setTtlInDays(int ttlInDays) {
        this.ttlInDays = ttlInDays;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApiKey apiKey = (ApiKey) o;
        return Objects.equals(getId(), apiKey.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId());
    }
}
