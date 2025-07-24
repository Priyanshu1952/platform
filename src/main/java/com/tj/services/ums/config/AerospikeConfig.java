//package com.tj.services.ums.config;
//
//import com.aerospike.client.AerospikeClient;
//import com.aerospike.client.Host;
//import com.aerospike.client.policy.ClientPolicy;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.data.aerospike.config.AbstractAerospikeDataConfiguration;
//import org.springframework.data.aerospike.repository.config.EnableAerospikeRepositories;
//
//import java.util.Collection;
//import java.util.Collections;
//
//@Configuration
//@EnableAerospikeRepositories(basePackages = "com.tj.services.ums.repository")
//public class AerospikeConfig extends AbstractAerospikeDataConfiguration {
//
//    @Value("${aerospike.host}")
//    private String host;
//
//    @Value("${aerospike.port}")
//    private int port;
//
//    @Value("${aerospike.namespace}")
//    private String namespace;
//
//    @Override
//    protected Collection<Host> getHosts() {
//        return Collections.singletonList(new Host(host, port));
//    }
//
//    @Override
//    protected String nameSpace() {
//        return namespace;
//    }
//
//    @Bean
//    public AerospikeClient aerospikeClient() {
//        ClientPolicy policy = new ClientPolicy();
//        policy.timeout = 2000;
//        return new AerospikeClient(policy, host, port);
//    }
//}