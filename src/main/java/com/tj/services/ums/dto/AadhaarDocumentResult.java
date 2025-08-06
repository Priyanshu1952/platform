package com.tj.services.ums.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AadhaarDocumentResult {
    private boolean verified;
    private String message;
    private AadhaarDocumentData extractedData;
    private String documentId; // For tracking stored documents
    private int statusCode;
}
