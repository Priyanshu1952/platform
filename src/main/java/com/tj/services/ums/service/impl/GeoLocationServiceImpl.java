package com.tj.services.ums.service.impl;

import com.tj.services.ums.config.SystemSecurityConfig;
import com.tj.services.ums.model.GeoLocation;
import com.tj.services.ums.repository.GeoLocationRepository;
import com.tj.services.ums.service.GeoLocationService;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class GeoLocationServiceImpl implements GeoLocationService {

    private static final SystemSecurityConfig.CIDRRange PROXY_IPS = null;
    private final GeoLocationRepository geoLocationRepository;

    public GeoLocationServiceImpl(GeoLocationRepository geoLocationRepository) {
        this.geoLocationRepository = geoLocationRepository;
    }

    @Override
    public Optional<GeoLocation> getLocationByIp(String ip) {
        return geoLocationRepository.findByIp(ip);
    }

    @Override
    public GeoLocation saveOrUpdateLocation(GeoLocation location) {
        return geoLocationRepository.save(location);
    }

    @Override
    public boolean existsByIp(String ip) {
        return geoLocationRepository.existsByIp(ip);
    }

    @Override
    public boolean isBlockedCountry(String remoteIp, List<String> blockedCountries) {
        return geoLocationRepository.findByIp(remoteIp)
                .map(loc -> blockedCountries.stream()
                        .map(String::toLowerCase)
                        .anyMatch(blocked -> blocked.equalsIgnoreCase(loc.getCountry())))
                .orElse(false); // or true, depending on whether unknown IPs should be considered blocked
    }

    @Override
    public Optional<GeoLocation> getLocationFromIp(String ip) {
        return geoLocationRepository.findByIp(ip);
    }


    @Override
    public boolean isProxyConnection(String ip) {
        return PROXY_IPS.contains(ip);
    }

}
