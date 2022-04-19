package io.arlas.ums.impl;

import io.arlas.ums.core.OrganisationDao;
import io.arlas.ums.model.Organisation;
import io.arlas.ums.model.OrganisationMember;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

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
        return currentSession().byNaturalId(Organisation.class).using("name", name).loadOptional();
    }

    @Override
    public void deleteOrganisation(Organisation organisation) {
        currentSession().delete(organisation);
    }

    @Override
    public Set<OrganisationMember> listUsers(Organisation organisation) {
        return organisation.getMembers();
    }
}
