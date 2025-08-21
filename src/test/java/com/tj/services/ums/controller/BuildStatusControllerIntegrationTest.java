package com.tj.services.ums.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class BuildStatusControllerIntegrationTest extends BaseIntegrationTest {

    @Test
    void testGetBuildStatus_Success() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/ums/v1/build-status")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.applicationName").exists())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.serverPort").exists())
                .andExpect(jsonPath("$.activeProfile").exists())
                .andExpect(jsonPath("$.version").exists())
                .andExpect(jsonPath("$.environment").exists())
                .andExpect(jsonPath("$.uptime").exists());
    }
} 