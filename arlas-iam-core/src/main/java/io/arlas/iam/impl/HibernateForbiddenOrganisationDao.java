package io.arlas.iam.impl;

import io.arlas.iam.core.ForbiddenOrganisationDao;
import io.arlas.iam.model.ForbiddenOrganisation;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Optional;

public class HibernateForbiddenOrganisationDao extends AbstractDAO<ForbiddenOrganisation> implements ForbiddenOrganisationDao {
    public HibernateForbiddenOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Optional<ForbiddenOrganisation> getName(String name) {
        return Optional.ofNullable(get(name));
    }

    @Override
    public ForbiddenOrganisation addName(ForbiddenOrganisation name) {
        return persist(name);
    }

    @Override
    public List<ForbiddenOrganisation> listNames() {
        return query("SELECT u FROM ForbiddenOrganisation u").getResultList();
    }

    @Override
    public void removeName(ForbiddenOrganisation name) {
        currentSession().remove(name);
    }
}
