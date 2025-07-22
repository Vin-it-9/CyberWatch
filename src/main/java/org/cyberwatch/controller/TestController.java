package org.cyberwatch.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
@Tag(name = "Attack Simulation Endpoints", description = "APIs to test the detection of various cyber attacks")
public class TestController {

    @Operation(summary = "Simple endpoint to test DDoS detection",
            description = "Hit this endpoint rapidly to trigger DDoS detection rules.")
    @ApiResponse(responseCode = "200", description = "Successful response")
    @GetMapping("/hello")
    public String hello() {
        return "Security Detection System is running!";
    }

    @Operation(summary = "Test SQL Injection Detection",
            description = "Provide classic SQL injection payloads in the 'input' or 'search' parameters.")
    @ApiResponse(responseCode = "200", description = "Input is reflected in the response.")
    @GetMapping("/vulnerable")
    public String vulnerableEndpoint(
            @Parameter(description = "Parameter vulnerable to SQLi.", example = "' OR 1=1--")
            @RequestParam(required = false) String input,
            @Parameter(description = "Another parameter vulnerable to SQLi.", example = "'; DROP TABLE users--")
            @RequestParam(required = false) String search) {
        return "Input received: " + (input != null ? input : "none") +
                ", Search: " + (search != null ? search : "none");
    }

    @Operation(summary = "Test Brute Force Detection",
            description = "Simulate multiple failed login attempts to trigger brute force alerts. The correct password is 'correct_password'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login attempt processed (could be success or failure).")
    })
    @PostMapping("/login")
    public String testLogin(
            @Parameter(description = "Username for login.", example = "admin") @RequestParam String username,
            @Parameter(description = "Password for login. Use any value other than 'correct_password' to fail.", example = "wrong_password_123") @RequestParam String password) {
        if (!"admin".equals(username) || !"correct_password".equals(password)) {
            return "Login failed for user: " + username;
        }
        return "Login successful for user: " + username;
    }

    @Operation(summary = "Test XSS Detection",
            description = "Provide an XSS payload in the 'comment' parameter.")
    @ApiResponse(responseCode = "200", description = "Comment is reflected in the response.")
    @GetMapping("/comment")
    public String addComment(
            @Parameter(description = "Parameter vulnerable to Cross-Site Scripting (XSS).", example = "<script>alert('XSS')</script>")
            @RequestParam String comment) {
        return "Comment added: " + comment;
    }

    @Operation(summary = "Test Directory Traversal Detection",
            description = "Provide a directory traversal payload in the 'filename' parameter.")
    @ApiResponse(responseCode = "200", description = "Filename is reflected in the response.")
    @GetMapping("/file")
    public String getFile(
            @Parameter(description = "Parameter vulnerable to Directory Traversal.", example = "../../../../etc/passwd")
            @RequestParam String filename) {
        return "Requested file: " + filename;
    }
}