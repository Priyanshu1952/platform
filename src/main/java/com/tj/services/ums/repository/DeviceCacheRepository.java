package com.tj.services.ums.repository;

import com.tj.services.ums.model.DeviceInfo;
import org.springframework.context.annotation.Profile;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.UUID;

@Profile("prod")
public interface DeviceCacheRepository extends CrudRepository<DeviceInfo, String> {
    List<DeviceInfo> findByUserId(UUID userId);
}
