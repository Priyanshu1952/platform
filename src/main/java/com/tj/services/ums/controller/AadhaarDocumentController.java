package com.tj.services.ums.controller;

import com.tj.services.ums.dto.AadhaarDocumentResult;
import com.tj.services.ums.dto.OtpRequestResult;
import com.tj.services.ums.service.AadhaarDocumentService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/aadhaar-document")
public class AadhaarDocumentController {

    @Autowired
    private AadhaarDocumentService aadhaarDocumentService;

    /**
     * Request OTP for e-Aadhaar download
     */
    @PostMapping("/request-otp")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<OtpRequestResult> requestEAadhaarOtp(
            @Valid @RequestBody AadhaarOtpRequest request,
            Authentication authentication) {
        
        String userId = authentication.getName();
        OtpRequestResult result = aadhaarDocumentService.requestEAadhaarOtp(request.getAadhaarNumber());
        return ResponseEntity.ok(result);
    }

    /**
     * Download e-Aadhaar PDF using OTP
     */
    @PostMapping("/download")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<byte[]> downloadEAadhaarPdf(
            @Valid @RequestBody EAadhaarDownloadRequest request,
            Authentication authentication) {
        
        String userId = authentication.getName();
        
        try {
            byte[] pdfBytes = aadhaarDocumentService.downloadEAadhaarPdf(
                request.getAadhaarNumber(), 
                request.getOtp(), 
                userId
            );
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "aadhaar_" + userId + ".pdf");
            
            return ResponseEntity.ok()
                .headers(headers)
                .body(pdfBytes);
                
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Upload and verify Aadhaar PDF
     */
    @PostMapping("/upload")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<AadhaarDocumentResult> uploadAadhaarPdf(
            @RequestParam("file") MultipartFile file,
            @RequestParam("aadhaarNumber") @NotBlank @Pattern(regexp = "\\d{12}", message = "Aadhaar number must be 12 digits") String aadhaarNumber,
            Authentication authentication) {
        
        String userId = authentication.getName();
        AadhaarDocumentResult result = aadhaarDocumentService.verifyAndStoreAadhaarPdf(file, aadhaarNumber, userId);
        
        if (result.getStatusCode() == 200) {
            return ResponseEntity.ok(result);
        } else {
            return ResponseEntity.status(result.getStatusCode()).body(result);
        }
    }

    /**
     * Get stored Aadhaar PDF for the authenticated user
     */
    @GetMapping("/download-stored")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<byte[]> getStoredAadhaarPdf(Authentication authentication) {
        String userId = authentication.getName();
        
        try {
            byte[] pdfBytes = aadhaarDocumentService.getStoredAadhaarPdf(userId);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "stored_aadhaar_" + userId + ".pdf");
            
            return ResponseEntity.ok()
                .headers(headers)
                .body(pdfBytes);
                
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.internalServerError().build();
        }
    }

    // Request DTOs
    public static class AadhaarOtpRequest {
        @NotBlank(message = "Aadhaar number is required")
        @Pattern(regexp = "\\d{12}", message = "Aadhaar number must be 12 digits")
        private String aadhaarNumber;

        public String getAadhaarNumber() { return aadhaarNumber; }
        public void setAadhaarNumber(String aadhaarNumber) { this.aadhaarNumber = aadhaarNumber; }
    }

    public static class EAadhaarDownloadRequest {
        @NotBlank(message = "Aadhaar number is required")
        @Pattern(regexp = "\\d{12}", message = "Aadhaar number must be 12 digits")
        private String aadhaarNumber;

        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must be 6 digits")
        private String otp;

        public String getAadhaarNumber() { return aadhaarNumber; }
        public void setAadhaarNumber(String aadhaarNumber) { this.aadhaarNumber = aadhaarNumber; }
        
        public String getOtp() { return otp; }
        public void setOtp(String otp) { this.otp = otp; }
    }
}
