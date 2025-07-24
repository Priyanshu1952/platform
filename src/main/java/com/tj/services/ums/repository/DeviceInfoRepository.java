package com.tj.services.ums.repository;

import com.tj.services.ums.model.DeviceInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface DeviceInfoRepository extends JpaRepository<DeviceInfo, Long> {

    Optional<DeviceInfo> findByFullDeviceId(String fullDeviceId);

    @Query("SELECT COUNT(d) FROM DeviceInfo d WHERE d.user.id = :userId")
    int countByUserId(String userId);

    @Query("SELECT d FROM DeviceInfo d WHERE d.user.id = :userId AND d.deviceType = :deviceType")
    List<DeviceInfo> findByUserAndDeviceType(String userId, String deviceType);

    @Query("SELECT d FROM DeviceInfo d WHERE d.user.id = :userId ORDER BY d.lastLoginTime DESC")
    List<DeviceInfo> findRecentDevices(String userId);

    @Query("SELECT COUNT(d) FROM DeviceInfo d WHERE d.user.id = :userId AND d.deviceType = :deviceType")
    int countByUserAndDeviceType(@Param("userId") String userId, @Param("deviceType") String deviceType);
}