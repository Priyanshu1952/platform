package com.tj.services.ums.filter;

import lombok.Data;

@Data
public class BaseFilter {
    private Integer page = 0;
    private Integer size = 20;
    private String sortBy = "createdOn";
    private String sortDir = "DESC";
} 