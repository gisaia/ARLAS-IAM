package io.arlas.auth.impl;

import io.arlas.auth.core.OrganisationDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.OrganisationMember;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class HibernateOrganisationDao extends AbstractDAO<Organisation> implements OrganisationDao {
    public HibernateOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation createOrganisation(Organisation organisation) {
        return persist(organisation);
    }

    @Override
    public Optional<Organisation> readOrganisation(UUID orgId) {
        return Optional.ofNullable(get(orgId));
    }

    @Override
    public Optional<Organisation> readOrganisation(String name) {
        return currentSession().byNaturalId(name).loadOptional();
    }

    @Override
    public void deleteOrganisation(Organisation organisation) {
        currentSession().delete(organisation);
    }

    @Override
    public Set<User> listUsers(User user) {
        return user.getOrganisations().stream()
                .flatMap(om -> om.getOrganisation().getMembers().stream())
                .map(OrganisationMember::getUser)
                .collect(Collectors.toSet());
    }
}
