package io.arlas.auth.impl;

import io.arlas.auth.core.OrganisationMemberDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.OrganisationMember;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

public class HibernateOrganisationMemberDao extends AbstractDAO<OrganisationMember> implements OrganisationMemberDao {
    public HibernateOrganisationMemberDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner) {
        persist(new OrganisationMember(user, organisation, isOwner));
        return organisation;
    }

    @Override
    public Organisation removeUserFromOrganisation(User user, Organisation organisation) {
        organisation.getMembers().forEach(om -> {
            if (om.getUser().getId() == user.getId()) {
                currentSession().delete(om);
            }
        });
        return organisation;
    }
}
