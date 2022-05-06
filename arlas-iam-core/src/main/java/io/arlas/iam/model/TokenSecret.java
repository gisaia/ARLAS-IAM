package io.arlas.iam.model;

import io.dropwizard.jackson.JsonSnakeCase;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Entity
@Table(name = "tokenSecret")
@JsonSnakeCase
public class TokenSecret {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @Column
    private byte[] secret;

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    private TokenSecret() {}

    public TokenSecret(byte[] secret){
        this.secret = secret;
    }

    public UUID getId() {
        return id;
    }

    private void setId(UUID id) {
        this.id = id;
    }

    public byte[] getSecret() {
        return secret;
    }

    private void setSecret(byte[] secret) {
        this.secret = secret;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }
}
