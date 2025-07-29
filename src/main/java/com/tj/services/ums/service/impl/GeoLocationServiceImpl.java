package com.tj.services.ums.service.impl;

import com.tj.services.ums.config.SystemSecurityConfig;
import com.tj.services.ums.model.GeoLocation;
import com.tj.services.ums.repository.GeoLocationRepository;
import com.tj.services.ums.service.GeoLocationService;
import jakarta.transaction.Transactional;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class GeoLocationServiceImpl implements GeoLocationService {

    @Value("${security.ip.proxy-ips:}")
    private List<String> proxyIpStrings;

    private List<SystemSecurityConfig.CIDRRange> PROXY_IPS = new ArrayList<>();

    private final GeoLocationRepository geoLocationRepository;

    public GeoLocationServiceImpl(GeoLocationRepository geoLocationRepository) {
        this.geoLocationRepository = geoLocationRepository;
    }

    @PostConstruct
    public void init() {
        if (proxyIpStrings != null) {
            this.PROXY_IPS = proxyIpStrings.stream()
                    .map(SystemSecurityConfig.CIDRRange::parse)
                    .filter(java.util.Objects::nonNull)
                    .collect(Collectors.toList());
        }
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
        if (PROXY_IPS.isEmpty()) {
            return false;
        }
        for (SystemSecurityConfig.CIDRRange range : PROXY_IPS) {
            if (range.contains(ip)) {
                return true;
            }
        }
        return false;
    }

}
