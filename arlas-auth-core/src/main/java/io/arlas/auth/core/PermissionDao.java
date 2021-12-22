package io.arlas.auth.core;

import io.arlas.auth.model.*;

import java.util.List;

public interface PermissionDao {

    List<Permission> listPermissions(String actingUserId, String targetUserId);

    Permission createPermission(String permission);

    User addPermissionToUser(String userId, String permissionId);

    User removePermissionFromUser(String userId, String permissionId);

}
