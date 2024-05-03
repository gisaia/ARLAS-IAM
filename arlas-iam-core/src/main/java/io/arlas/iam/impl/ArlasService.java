package io.arlas.iam.impl;

import io.arlas.client.ApiClient;
import io.arlas.client.ApiException;
import io.arlas.client.api.CollectionsApi;
import io.arlas.client.model.CollectionReference;
import io.arlas.commons.rest.utils.ServerConstants;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import jakarta.ws.rs.core.HttpHeaders;

import java.util.List;

public class ArlasService {
    private final String arlasServerBasePath;

    public ArlasService(ArlasAuthServerConfiguration conf) {
        this.arlasServerBasePath = conf.arlasServerBasePath;
    }

    public List<String> getCollections(String organisation, String token) throws ApiException {
        return new CollectionsApi(
                new ApiClient()
                        .setBasePath(arlasServerBasePath)
                        .addDefaultHeader(HttpHeaders.AUTHORIZATION, token)
                        .addDefaultHeader(ServerConstants.ARLAS_ORG_FILTER, organisation))
                .getAll(false)
                .stream()
                .map(CollectionReference::getCollectionName)
                .toList();
    }
}
