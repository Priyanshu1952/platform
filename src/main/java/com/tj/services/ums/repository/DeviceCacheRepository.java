package com.tj.services.ums.repository;

import com.tj.services.ums.model.DeviceInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.aerospike.repository.AerospikeRepository;

import java.util.List;
import java.util.UUID;

public interface DeviceCacheRepository extends JpaRepository<DeviceInfo, String> {
    List<DeviceInfo> findByUserId(UUID userId);
}
