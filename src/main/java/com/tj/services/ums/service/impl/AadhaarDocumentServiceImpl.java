package com.tj.services.ums.service.impl;

import com.tj.services.ums.dto.AadhaarDocumentData;
import com.tj.services.ums.dto.AadhaarDocumentResult;
import com.tj.services.ums.dto.OtpRequestResult;
import com.tj.services.ums.service.AadhaarDocumentService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.UUID;

@Service
public class AadhaarDocumentServiceImpl implements AadhaarDocumentService {

    private final WebClient webClient;
    
    @Value("${surepass.api.url}")
    private String surepassApiUrl;
    
    @Value("${surepass.api.token}")
    private String apiToken;
    
    // Document storage path (in production, use cloud storage like AWS S3)
    private final String documentStoragePath = "documents/aadhaar/";

    public AadhaarDocumentServiceImpl(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("https://kyc-api.surepass.io").build();
        
        // Create document storage directory if it doesn't exist
        try {
            Files.createDirectories(Paths.get(documentStoragePath));
        } catch (IOException e) {
            System.err.println("Failed to create document storage directory: " + e.getMessage());
        }
    }

    @Override
    public byte[] downloadEAadhaarPdf(String aadhaarNumber, String otp, String userId) {
        System.out.println("Initiating e-Aadhaar PDF download for user: " + userId + " with Aadhaar: " + aadhaarNumber);
        
        try {
            // This would integrate with official UIDAI APIs or Surepass e-Aadhaar download API
            // For now, returning mock implementation
            
            // In real implementation, you would:
            // 1. Call UIDAI e-Aadhaar download API with Aadhaar number and OTP
            // 2. Receive the PDF bytes
            // 3. Store the document securely
            // 4. Return the PDF bytes
            
            System.out.println("Mock: e-Aadhaar PDF download would happen here");
            return new byte[0]; // Mock implementation
            
        } catch (Exception e) {
            System.err.println("Error downloading e-Aadhaar PDF: " + e.getMessage());
            throw new RuntimeException("Failed to download e-Aadhaar PDF: " + e.getMessage());
        }
    }

    @Override
    public AadhaarDocumentResult verifyAndStoreAadhaarPdf(MultipartFile file, String aadhaarNumber, String userId) {
        System.out.println("Verifying and storing Aadhaar PDF for user: " + userId);
        
        try {
            // Validate file
            if (file.isEmpty()) {
                return new AadhaarDocumentResult(false, "File is empty", null, null, 400);
            }
            
            if (!"application/pdf".equals(file.getContentType())) {
                return new AadhaarDocumentResult(false, "File must be a PDF", null, null, 400);
            }
            
            // Extract data from PDF using Surepass e-Aadhaar API
            byte[] pdfBytes = file.getBytes();
            AadhaarDocumentData extractedData = extractDataFromPdf(pdfBytes);
            
            // Verify that extracted Aadhaar number matches expected
            if (extractedData != null && !aadhaarNumber.equals(extractedData.getAadhaarNumber())) {
                return new AadhaarDocumentResult(false, "Aadhaar number in document does not match provided number", extractedData, null, 400);
            }
            
            // Store the document
            String documentId = storeDocument(pdfBytes, userId);
            
            return new AadhaarDocumentResult(true, "Aadhaar PDF verified and stored successfully", extractedData, documentId, 200);
            
        } catch (Exception e) {
            System.err.println("Error verifying Aadhaar PDF: " + e.getMessage());
            return new AadhaarDocumentResult(false, "Failed to verify PDF: " + e.getMessage(), null, null, 500);
        }
    }

    @Override
    public byte[] getStoredAadhaarPdf(String userId) {
        try {
            Path filePath = Paths.get(documentStoragePath + userId + "_aadhaar.pdf");
            if (Files.exists(filePath)) {
                return Files.readAllBytes(filePath);
            } else {
                throw new RuntimeException("Aadhaar PDF not found for user: " + userId);
            }
        } catch (IOException e) {
            System.err.println("Error retrieving stored Aadhaar PDF: " + e.getMessage());
            throw new RuntimeException("Failed to retrieve Aadhaar PDF: " + e.getMessage());
        }
    }

    @Override
    public AadhaarDocumentData extractDataFromPdf(byte[] pdfBytes) {
        System.out.println("Extracting data from Aadhaar PDF using Surepass e-Aadhaar API");
        
        try {
            // This would call Surepass e-Aadhaar API to extract data from PDF
            // For now, returning mock data
            
            // In real implementation:
            // 1. Convert PDF bytes to base64 or multipart form data
            // 2. Call Surepass e-Aadhaar extraction API
            // 3. Parse response and extract Aadhaar data
            // 4. Return structured data
            
            System.out.println("Mock: PDF data extraction would happen here via Surepass API");
            
            // Mock extracted data
            AadhaarDocumentData mockData = new AadhaarDocumentData();
            mockData.setAadhaarNumber("XXXX XXXX XXXX"); // Masked for security
            mockData.setFullName("Mock Name");
            mockData.setDateOfBirth("01/01/1990");
            mockData.setGender("M");
            mockData.setAddress("Mock Address");
            mockData.setPincode("123456");
            mockData.setState("Mock State");
            mockData.setDistrict("Mock District");
            
            return mockData;
            
        } catch (Exception e) {
            System.err.println("Error extracting data from Aadhaar PDF: " + e.getMessage());
            throw new RuntimeException("Failed to extract data from PDF: " + e.getMessage());
        }
    }

    @Override
    public OtpRequestResult requestEAadhaarOtp(String aadhaarNumber) {
        System.out.println("Requesting OTP for e-Aadhaar download: " + aadhaarNumber);
        
        try {
            // This would integrate with official UIDAI APIs for OTP generation
            // For now, returning mock implementation
            
            // In real implementation:
            // 1. Call UIDAI OTP generation API
            // 2. Return transaction ID for OTP session
            
            String transactionId = UUID.randomUUID().toString();
            System.out.println("Mock: OTP request would be sent to registered mobile/email");
            
            return new OtpRequestResult(true, "OTP sent to registered mobile/email", transactionId, 200);
            
        } catch (Exception e) {
            System.err.println("Error requesting e-Aadhaar OTP: " + e.getMessage());
            return new OtpRequestResult(false, "Failed to request OTP: " + e.getMessage(), null, 500);
        }
    }
    
    private String storeDocument(byte[] pdfBytes, String userId) throws IOException {
        String documentId = UUID.randomUUID().toString();
        Path filePath = Paths.get(documentStoragePath + userId + "_aadhaar.pdf");
        Files.write(filePath, pdfBytes);
        System.out.println("Stored Aadhaar PDF for user: " + userId + " at: " + filePath);
        return documentId;
    }
}
