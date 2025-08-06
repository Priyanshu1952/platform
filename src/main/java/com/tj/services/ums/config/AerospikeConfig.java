package com.tj.services.ums.config;

import com.aerospike.client.AerospikeClient;
import com.aerospike.client.Host;
import com.aerospike.client.policy.ClientPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("prod")
public class AerospikeConfig {

    @Value("${aerospike.hosts:localhost:3000}")
    private String hosts;

    

    @Bean(destroyMethod = "close")
    public AerospikeClient aerospikeClient() {
        ClientPolicy policy = new ClientPolicy();
        policy.timeout = 2000;
        String[] hostPorts = hosts.split(",");
        Host[] aerospikeHosts = new Host[hostPorts.length];
        for (int i = 0; i < hostPorts.length; i++) {
            String[] parts = hostPorts[i].split(":");
            aerospikeHosts[i] = new Host(parts[0], Integer.parseInt(parts[1]));
        }
        return new AerospikeClient(policy, aerospikeHosts);
    }
}