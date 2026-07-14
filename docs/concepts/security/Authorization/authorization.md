---
title: "Authorization in Spring Boot with Method-Level Security"
sidebar_label: "Authorization & Method Security"
sidebar_position: 8
description: "Complete guide to implementing role-based and ownership-based authorization in Spring Boot using @PreAuthorize, @PostAuthorize, custom annotations, UserPrincipal, and AuthorizationService. Includes best practices, design patterns, and real-world examples for secure API development."
tags: [spring-boot, security, authorization, rbac, method-security, access-control, ownership-based-access]
---

# Authorization in Spring Boot with Method-Level Security

:::tip Summary
- Use **Method Security** (`@PreAuthorize`, `@PostAuthorize`) for fine-grained control on individual methods.
- Combine **Role-based Authorization** (e.g., "Is user ADMIN?") with **Ownership-based Authorization** (e.g., "Is this my data?").
- Use `UserPrincipal` to inject authenticated user info without database lookups.
- Create **AuthorizationService** for reusable authorization logic and custom business rules.
- Design **custom annotations** (`@RequireRole`, `@IsCurrentUser`, `@CanModify`) for clean, readable controller code.
- Follow **least privilege principle**: deny by default, grant only what's needed.
- **Test authorization** thoroughly: unit tests for service logic, integration tests for endpoints.
:::

:::note Prerequisites
This guide assumes you have:
- Spring Security configured with `SecurityConfig`
- Custom UserDetailsService & UserPrincipal implemented
- JWT or session-based authentication in place
- Basic understanding of Spring Security concepts (Authentication, Authorization, GrantedAuthority)
:::

---

## 1. Overview: Authentication vs. Authorization

### Quick Reference

| Concept | Definition | Example |
|---------|-----------|---------|
| **Authentication** | "Who are you?" | User logs in with username/password → JWT token issued |
| **Authorization** | "What can you do?" | User with ADMIN role can delete users; USER role cannot |
| **Least Privilege** | Grant minimum needed permissions | User role can only view own profile, not others |
| **Role-Based Access** | Rules based on user roles | All ADMINs have same permissions |
| **Ownership-Based Access** | Rules based on resource ownership | User can edit only their own posts |
| **Attribute-Based Access** | Rules based on attributes | Edit blog if published=true AND author=currentUser |

### Authorization Flow in Spring Boot

```
HTTP Request
    ↓
JwtAuthenticationFilter (extract token, set Authentication in SecurityContext)
    ↓
SecurityFilterChain (HTTP-level checks: public endpoints, require login)
    ↓
Controller Method (@PreAuthorize: fine-grained authorization)
    ↓
AuthorizationService (complex business logic checks)
    ↓
Response or 403 Forbidden
```

---

## 2. Foundation: UserPrincipal & Custom UserDetailsService

### Why UserPrincipal?

Default Spring Security `User` object has only username and authorities. You likely need:
- User ID
- Email
- First/last name
- Department
- Custom attributes

**Solution**: Create a `UserPrincipal` class implementing `UserDetails`.

### UserPrincipal Implementation

```java
package com.jdnbrothers.tlms.security.principal;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom UserPrincipal carrying user metadata needed for authorization.
 * This avoids repeated database lookups during authorization checks.
 * 
 * Best Practice: Keep this lightweight - only what's needed for auth decisions.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserPrincipal implements UserDetails {

    private Long id;                    // User ID - critical for ownership checks
    private String username;
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private Boolean isActive;
    
    private Set<String> roleNames;      // e.g., {"ADMIN", "USER"}
    private Set<String> permissions;    // e.g., {"READ_USER", "WRITE_USER"}
    
    // ===== UserDetails Implementation =====

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Convert role names to GrantedAuthority objects
        return roleNames.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive;
    }

    // ===== Convenience Methods for Authorization =====

    /**
     * Check if this user has a specific role.
     * Usage: userPrincipal.hasRole("ADMIN")
     */
    public boolean hasRole(String roleName) {
        return roleNames.contains(roleName);
    }

    /**
     * Check if user has ANY of the given roles.
     */
    public boolean hasAnyRole(String... roleNames) {
        return Arrays.stream(roleNames)
            .anyMatch(this.roleNames::contains);
    }

    /**
     * Check if user has ALL of the given roles.
     */
    public boolean hasAllRoles(String... roleNames) {
        return Arrays.stream(roleNames)
            .allMatch(this.roleNames::contains);
    }

    /**
     * Check if user has a specific permission.
     */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    /**
     * Full name convenience method.
     */
    public String getFullName() {
        return (firstName != null && lastName != null) 
            ? firstName + " " + lastName 
            : username;
    }
}
```

### Custom UserDetailsService

```java
package com.jdnbrothers.tlms.service.security;

import com.jdnbrothers.tlms.entity.User;
import com.jdnbrothers.tlms.repository.UserRepository;
import com.jdnbrothers.tlms.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/**
 * Load user details from database and convert to UserPrincipal.
 * Called by Spring Security during authentication and by JWT filter.
 * 
 * Best Practice: Cache the result if database lookups are expensive.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return UserPrincipal.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .password(user.getPassword())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .isActive(user.getIsActive())
            // Convert roles to role names (strip "ROLE_" prefix)
            .roleNames(user.getRoles().stream()
                .map(role -> role.getName().toUpperCase())
                .collect(Collectors.toSet()))
            // Extract permissions from roles
            .permissions(user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(p -> p.getCode())
                .collect(Collectors.toSet()))
            .build();
    }
}
```

---

## 3. Enable Method Security

### Configuration

```java
package com.jdnbrothers.tlms.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    prePostEnabled = true,      // Enable @PreAuthorize and @PostAuthorize
    securedEnabled = true,      // Enable @Secured (legacy, discouraged)
    jsr250Enabled = true        // Enable @RolesAllowed (JSR-250 standard)
)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> {})
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // URL-level rules: only distinguish public vs. authenticated
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/auth/login", "/api/auth/refresh").permitAll()
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                
                // All others require authentication; role checks happen at method level
                .anyRequest().authenticated())
            
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                .accessDeniedHandler(new CustomAccessDeniedHandler()))
            
            .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

**Key Point**: HTTP-level rules only distinguish public vs. authenticated. Fine-grained role/ownership checks happen at **method level**.

---

## 4. AuthorizationService: Reusable Authorization Logic

### Why AuthorizationService?

- **DRY Principle**: Avoid repeating authorization logic across controllers
- **Testability**: Test authorization logic in isolation
- **Business Logic**: Encapsulate complex ownership/attribute checks
- **Caching**: Cache expensive checks (e.g., team membership)

### Full Implementation

```java
package com.jdnbrothers.tlms.service.security;

import com.jdnbrothers.tlms.entity.User;
import com.jdnbrothers.tlms.repository.UserRepository;
import com.jdnbrothers.tlms.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * Centralized authorization service for reusable role and ownership checks.
 * 
 * Best Practices:
 * 1. All @PreAuthorize expressions should delegate to this service
 * 2. Encapsulate complex business logic (e.g., team membership)
 * 3. Cache expensive checks (database lookups)
 * 4. Log authorization failures for audit trail
 * 5. Use descriptive method names that read like English
 * 
 * Usage in controllers:
 *   @PreAuthorize("@authService.canViewUser(#userId)")
 *   @PreAuthorize("@authService.isAdminOrOwner(#resourceId)")
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final UserRepository userRepository;

    // ===== Authentication Status Checks =====

    /**
     * Get the current authenticated user as UserPrincipal.
     * Returns null if not authenticated.
     */
    public UserPrincipal getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        return auth.getPrincipal() instanceof UserPrincipal 
            ? (UserPrincipal) auth.getPrincipal() 
            : null;
    }

    /**
     * Get current user ID. Useful when you don't need full UserPrincipal.
     */
    public Long getCurrentUserId() {
        UserPrincipal user = getCurrentUser();
        return user != null ? user.getId() : null;
    }

    /**
     * Get current username.
     */
    public String getCurrentUsername() {
        UserPrincipal user = getCurrentUser();
        return user != null ? user.getUsername() : null;
    }

    // ===== Role-Based Checks =====

    /**
     * Check if current user has a specific role.
     * 
     * @param roleName the role name (e.g., "ADMIN", "MANAGER", "USER")
     * @return true if user has the role
     */
    public boolean hasRole(String roleName) {
        UserPrincipal user = getCurrentUser();
        return user != null && user.hasRole(roleName);
    }

    /**
     * Check if current user has ANY of the given roles.
     * 
     * Usage: @PreAuthorize("@authService.hasAnyRole('ADMIN', 'MANAGER')")
     */
    public boolean hasAnyRole(String... roleNames) {
        UserPrincipal user = getCurrentUser();
        return user != null && user.hasAnyRole(roleNames);
    }

    /**
     * Check if current user has ALL of the given roles.
     * 
     * Usage: @PreAuthorize("@authService.hasAllRoles('ADMIN', 'REVIEWER')")
     */
    public boolean hasAllRoles(String... roleNames) {
        UserPrincipal user = getCurrentUser();
        return user != null && user.hasAllRoles(roleNames);
    }

    /**
     * Check if current user is admin.
     * 
     * Usage: @PreAuthorize("@authService.isAdmin()")
     */
    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    /**
     * Check if current user is manager.
     */
    public boolean isManager() {
        return hasRole("MANAGER");
    }

    /**
     * Check if current user is instructor.
     */
    public boolean isInstructor() {
        return hasRole("INSTRUCTOR");
    }

    /**
     * Check if current user is student.
     */
    public boolean isStudent() {
        return hasRole("STUDENT");
    }

    // ===== Ownership-Based Checks =====

    /**
     * Check if current user is the specified user (owns the account).
     * 
     * Usage: @PreAuthorize("@authService.isCurrentUser(#userId)")
     */
    public boolean isCurrentUser(Long userId) {
        Long currentUserId = getCurrentUserId();
        return currentUserId != null && currentUserId.equals(userId);
    }

    /**
     * Check if current user owns a resource (by resource owner ID).
     * 
     * Usage: @PreAuthorize("@authService.isResourceOwner(#resourceId)")
     * Note: Implement based on your resource entity
     */
    public boolean isResourceOwner(Long resourceId) {
        // Example implementation:
        // Resource resource = resourceRepository.findById(resourceId).orElse(null);
        // return resource != null && isCurrentUser(resource.getOwnerId());
        
        Long currentUserId = getCurrentUserId();
        return currentUserId != null; // Placeholder
    }

    // ===== Combined Role + Ownership Checks (Most Common) =====

    /**
     * Check if admin OR owner of resource.
     * 
     * Usage: @PreAuthorize("@authService.isAdminOrOwner(#userId)")
     * Common for: viewing/editing user profiles, resources
     */
    public boolean isAdminOrOwner(Long userId) {
        return isAdmin() || isCurrentUser(userId);
    }

    /**
     * Check if admin OR manager OR owner.
     * 
     * Usage: @PreAuthorize("@authService.isAdminManagerOrOwner(#teamId)")
     * Common for: team management
     */
    public boolean isAdminManagerOrOwner(Long resourceId) {
        return isAdmin() || isManager() || isResourceOwner(resourceId);
    }

    /**
     * Check if can view user.
     * Rules: Admin can view anyone; User can view only themselves
     * 
     * Usage: @PreAuthorize("@authService.canViewUser(#userId)")
     */
    public boolean canViewUser(Long userId) {
        return isAdmin() || isCurrentUser(userId);
    }

    /**
     * Check if can edit user.
     * Rules: Admin can edit anyone; User can edit only themselves
     * 
     * Usage: @PreAuthorize("@authService.canEditUser(#userId)")
     */
    public boolean canEditUser(Long userId) {
        return isAdmin() || isCurrentUser(userId);
    }

    /**
     * Check if can delete user.
     * Rules: Only Admin can delete
     * 
     * Usage: @PreAuthorize("@authService.canDeleteUser(#userId)")
     */
    public boolean canDeleteUser(Long userId) {
        // Prevent users from deleting themselves
        return isAdmin() && !isCurrentUser(userId);
    }

    /**
     * Check if can change user roles.
     * Rules: Only Admin can change roles
     * 
     * Usage: @PreAuthorize("@authService.canChangeRoles(#userId)")
     */
    public boolean canChangeRoles(Long userId) {
        // Admin can change anyone's role except their own (optional)
        return isAdmin() && !isCurrentUser(userId);
    }

    /**
     * Check if can access sensitive reports.
     * Rules: Only Admin and Manager
     * 
     * Usage: @PreAuthorize("@authService.canAccessReports()")
     */
    public boolean canAccessReports() {
        return hasAnyRole("ADMIN", "MANAGER");
    }

    /**
     * Check if can access audit logs.
     * Rules: Only Admin
     * 
     * Usage: @PreAuthorize("@authService.canAccessAuditLogs()")
     */
    public boolean canAccessAuditLogs() {
        return isAdmin();
    }

    // ===== Attribute-Based Checks (Advanced) =====

    /**
     * Check if user has a specific permission.
     * More granular than role-based (e.g., MANAGE_USERS, DELETE_RESOURCES)
     * 
     * Usage: @PreAuthorize("@authService.hasPermission('DELETE_USER')")
     */
    public boolean hasPermission(String permissionCode) {
        UserPrincipal user = getCurrentUser();
        return user != null && user.hasPermission(permissionCode);
    }

    /**
     * Check if user is member of a team (example of complex ownership).
     * Typically requires database lookup, so marked with @Cacheable.
     * 
     * Usage: @PreAuthorize("@authService.isTeamMember(#teamId)")
     */
    @Cacheable(value = "teamMembership", key = "#teamId + '-' + #userId", unless = "#result == false")
    public boolean isTeamMember(Long teamId, Long userId) {
        // Example implementation:
        // return teamRepository.findById(teamId)
        //     .map(team -> team.getMembers().stream()
        //         .anyMatch(member -> member.getId().equals(userId)))
        //     .orElse(false);
        
        return true; // Placeholder
    }

    /**
     * Check if user is team lead (has leadership role in team).
     * 
     * Usage: @PreAuthorize("@authService.isTeamLead(#teamId)")
     */
    @Cacheable(value = "teamLeadership", key = "#teamId + '-' + #userId", unless = "#result == false")
    public boolean isTeamLead(Long teamId, Long userId) {
        // Example implementation:
        // return teamRepository.findById(teamId)
        //     .map(team -> team.getLeadId().equals(userId))
        //     .orElse(false);
        
        return true; // Placeholder
    }

    // ===== Logging & Audit =====

    /**
     * Log authorization check (audit trail).
     * Call this in complex authorization paths for compliance.
     */
    public void logAuthorizationCheck(String action, Long resourceId, boolean allowed) {
        String username = getCurrentUsername();
        if (allowed) {
            log.info("Authorization check PASSED: user={}, action={}, resourceId={}", 
                username, action, resourceId);
        } else {
            log.warn("Authorization check FAILED: user={}, action={}, resourceId={}", 
                username, action, resourceId);
        }
    }
}
```

---

## 5. Using @PreAuthorize in Controllers

### Basic Patterns

```java
package com.jdnbrothers.tlms.controller;

import com.jdnbrothers.tlms.security.principal.UserPrincipal;
import com.jdnbrothers.tlms.service.security.AuthorizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * User Management API
 * 
 * Authorization Rules:
 * - GET /api/users/{id}: Admin OR owner
 * - PUT /api/users/{id}: Admin OR owner
 * - DELETE /api/users/{id}: Admin only (not own)
 * - POST /api/users: Admin only
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthorizationService authService;

    // ===== PUBLIC (No Authentication) =====

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        // Anyone can register
        return ResponseEntity.ok(userService.register(request));
    }

    // ===== AUTHENTICATED (Any logged-in user) =====

    /**
     * Get own profile
     * @PreAuthorize("isAuthenticated()") - any logged-in user
     */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getOwnProfile(Authentication auth) {
        UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
        return ResponseEntity.ok(userService.getUserById(principal.getId()));
    }

    /**
     * Update own profile
     */
    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updateOwnProfile(
            Authentication auth,
            @RequestBody UpdateUserRequest request) {
        UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
        return ResponseEntity.ok(userService.updateUser(principal.getId(), request));
    }

    /**
     * Change own password
     */
    @PostMapping("/me/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> changePassword(
            Authentication auth,
            @RequestBody ChangePasswordRequest request) {
        UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
        userService.changePassword(principal.getId(), request);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    // ===== ROLE-BASED (Only specific roles) =====

    /**
     * Get all users (Admin only)
     * @PreAuthorize("hasRole('ADMIN')") - only ADMIN role
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(userService.getAllUsers(page, size));
    }

    /**
     * Create new user (Admin only)
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest request) {
        UserDTO user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    /**
     * Update user roles (Admin only)
     * Best practice: prevent admin from removing their own admin role
     */
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserRoles(
            @PathVariable Long id,
            @RequestBody UpdateRolesRequest request,
            Authentication auth) {
        
        UserPrincipal admin = (UserPrincipal) auth.getPrincipal();
        
        // Security check: prevent removing own admin role
        if (admin.getId().equals(id) && !request.getRoles().contains("ADMIN")) {
            return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Cannot remove your own admin role"));
        }
        
        return ResponseEntity.ok(userService.updateRoles(id, request.getRoles()));
    }

    // ===== MULTIPLE ROLES (Admin OR Manager) =====

    /**
     * Get reports (Admin or Manager)
     * @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')") - either role allowed
     */
    @GetMapping("/reports")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> getReports() {
        return ResponseEntity.ok(userService.generateReports());
    }

    /**
     * Export user data (Admin or Manager)
     */
    @PostMapping("/export")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> exportUsers(@RequestParam String format) {
        byte[] data = userService.exportUsers(format);
        return ResponseEntity
            .ok()
            .header("Content-Disposition", "attachment; filename=\"users.xlsx\"")
            .body(data);
    }

    // ===== OWNERSHIP-BASED (Owner OR Admin) =====

    /**
     * Get specific user (Admin OR owner)
     * @PreAuthorize delegates to service method that checks both conditions
     */
    @GetMapping("/{id}")
    @PreAuthorize("@authService.canViewUser(#id)")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    /**
     * Update specific user (Admin OR owner)
     */
    @PutMapping("/{id}")
    @PreAuthorize("@authService.canEditUser(#id)")
    public ResponseEntity<?> updateUser(
            @PathVariable Long id,
            @RequestBody UpdateUserRequest request) {
        return ResponseEntity.ok(userService.updateUser(id, request));
    }

    /**
     * Delete user (Admin only, cannot delete self)
     * @PreAuthorize delegates to service that prevents self-deletion
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("@authService.canDeleteUser(#id)")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    // ===== COMPLEX CHECKS =====

    /**
     * Deactivate user account (Admin OR owner)
     * Additional check: cannot deactivate if only admin
     */
    @PostMapping("/{id}/deactivate")
    @PreAuthorize("@authService.isAdminOrOwner(#id)")
    public ResponseEntity<?> deactivateUser(
            @PathVariable Long id,
            Authentication auth) {
        
        // Verify: don't deactivate the only admin
        if (userService.isOnlyAdmin(id)) {
            return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Cannot deactivate the only admin user"));
        }
        
        userService.deactivateUser(id);
        return ResponseEntity.ok(Map.of("message", "User deactivated"));
    }

    /**
     * Resend verification email (Admin OR owner)
     * Example: combines role check with parameter-based ownership check
     */
    @PostMapping("/{id}/resend-verification")
    @PreAuthorize("@authService.isAdminOrOwner(#id)")
    public ResponseEntity<?> resendVerificationEmail(@PathVariable Long id) {
        userService.sendVerificationEmail(id);
        return ResponseEntity.ok(Map.of("message", "Verification email sent"));
    }
}
```

---

## 6. @PostAuthorize: Check After Execution

Use when you need to filter results or validate against returned data:

```java
package com.jdnbrothers.tlms.controller;

import org.springframework.security.access.prepost.PostAuthorize;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    /**
     * Get document only if current user is author OR admin.
     * Note: @PostAuthorize is less efficient than @PreAuthorize 
     * (executes method first). Use only when necessary.
     * 
     * returnObject refers to the returned Document object
     */
    @GetMapping("/{id}")
    @PostAuthorize("returnObject.authorId == authentication.principal.id or hasRole('ADMIN')")
    public Document getDocument(@PathVariable Long id) {
        // Method executes first, then authorization is checked
        return documentService.getDocument(id);
    }

    /**
     * Better approach: use @PreAuthorize with a service method
     */
    @GetMapping("/{id}/v2")
    @PreAuthorize("@authService.canViewDocument(#id)")
    public Document getDocumentV2(@PathVariable Long id) {
        // Check happens BEFORE method execution (more efficient)
        return documentService.getDocument(id);
    }
}
```

---

## 7. Custom Annotations: Making Code More Readable

Create reusable custom annotations for common patterns:

```java
package com.jdnbrothers.tlms.security.annotation;

import org.springframework.security.access.prepost.PreAuthorize;
import java.lang.annotation.*;

/**
 * Indicates endpoint requires Admin role
 * 
 * Instead of:
 *   @PreAuthorize("hasRole('ADMIN')")
 * 
 * Use:
 *   @RequireAdmin
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('ADMIN')")
public @interface RequireAdmin {
}

/**
 * Indicates endpoint requires any of the specified roles
 * 
 * Usage:
 *   @RequireAnyRole({"ADMIN", "MANAGER"})
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyRole({'ADMIN', 'MANAGER'})")
public @interface RequireManager {
}

/**
 * Indicates endpoint requires authentication
 * 
 * Usage:
 *   @RequireAuth
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("isAuthenticated()")
public @interface RequireAuth {
}

/**
 * Indicates endpoint requires current user OR admin
 * 
 * Usage:
 *   @RequireOwnerOrAdmin
 *   public ResponseEntity getUser(@PathVariable Long id) { ... }
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireOwnerOrAdmin {
    // Allows more flexible implementation via @interface
}
```

Usage in controllers:

```java
@RestController
@RequestMapping("/api/admin")
@RequireAdmin  // All methods require ADMIN
public class AdminController {

    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        // Inherits @RequireAdmin from class level
    }
}

@RestController
@RequestMapping("/api/managers")
@RequireManager  // All methods require MANAGER role
public class ManagerController {
    // ...
}
```

---

## 8. Best Practices

### 8.1 Principle of Least Privilege

**Rule**: Default to DENY, grant minimum permissions needed.

```java
// ❌ DON'T: Assume endpoint is safe if you "forgot" @PreAuthorize
@GetMapping("/sensitive-data")
public ResponseEntity<?> getData() {
    // DANGEROUS: if @PreAuthorize is missing, anyone can access
}

// ✅ DO: Explicitly protect all endpoints
@GetMapping("/sensitive-data")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> getData() {
    // Safe: only ADMIN can access
}

// ✅ DO: Even better, fail explicitly
@GetMapping("/sensitive-data")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> getData() {
    if (!authService.isAdmin()) {
        throw new AccessDeniedException("Unauthorized");
    }
    // Extra safety check
}
```

### 8.2 Use Service Methods for Complex Checks

```java
// ❌ DON'T: Complex logic in @PreAuthorize expression
@PreAuthorize("hasRole('ADMIN') or (hasRole('MANAGER') and @userService.getUser(#userId).getDepartment() == authentication.principal.getDepartment())")
public ResponseEntity<?> updateUser(@PathVariable Long userId) { }

// ✅ DO: Extract to service method
@PreAuthorize("@authService.canManageUser(#userId)")
public ResponseEntity<?> updateUser(@PathVariable Long userId) { }

// In AuthorizationService:
public boolean canManageUser(Long userId) {
    if (isAdmin()) return true;
    
    if (!isManager()) return false;
    
    User user = userRepository.findById(userId).orElse(null);
    if (user == null) return false;
    
    return user.getDepartment().equals(getCurrentUserDepartment());
}
```

### 8.3 Always Check on Backend

Never trust frontend authorization checks:

```java
// ❌ DON'T: Only protect in frontend
// Frontend: if (user.role === 'ADMIN') showAdminButton = true;

// ✅ DO: Always protect backend endpoint
@DeleteMapping("/users/{id}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userService.delete(id);
    return ResponseEntity.ok("Deleted");
}
```

### 8.4 Prevent Self-Damage

```java
@PreAuthorize("hasRole('ADMIN')")
@PutMapping("/users/{id}/roles")
public ResponseEntity<?> updateRoles(
        @PathVariable Long id,
        @RequestBody UpdateRolesRequest request,
        Authentication auth) {
    
    UserPrincipal admin = (UserPrincipal) auth.getPrincipal();
    
    // ✅ Prevent admin from removing their own admin role
    if (admin.getId().equals(id) && !request.getRoles().contains("ADMIN")) {
        return ResponseEntity
            .status(HttpStatus.FORBIDDEN)
            .body(Map.of("error", "Cannot remove your own admin role"));
    }
    
    return ResponseEntity.ok(userService.updateRoles(id, request.getRoles()));
}
```

### 8.5 Fail Safely

```java
// ❌ DON'T: Assume user exists or permission is granted
@PreAuthorize("@authService.isAdmin()")
@DeleteMapping("/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userService.deleteUser(id); // What if user doesn't exist?
}

// ✅ DO: Validate and handle edge cases
@PreAuthorize("@authService.isAdmin()")
@DeleteMapping("/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    try {
        userService.deleteUser(id);
        return ResponseEntity.ok("User deleted");
    } catch (EntityNotFoundException e) {
        return ResponseEntity.notFound().build();
    }
}
```

### 8.6 Cache Expensive Checks

```java
// ❌ DON'T: Database lookup on every request
public boolean isTeamMember(Long teamId) {
    return teamRepository.findById(teamId)
        .map(team -> team.getMembers().contains(getCurrentUser()))
        .orElse(false);
}

// ✅ DO: Cache the result
@Cacheable(value = "teamMembership", key = "#teamId + '-' + #userId")
public boolean isTeamMember(Long teamId, Long userId) {
    return teamRepository.findById(teamId)
        .map(team -> team.getMembers().stream()
            .anyMatch(m -> m.getId().equals(userId)))
        .orElse(false);
}

// ✅ DO: Invalidate when team membership changes
@CacheEvict(value = "teamMembership", key = "#teamId + '-' + #userId")
public void addMember(Long teamId, Long userId) {
    // ...
}
```

### 8.7 Handle Access Denied Gracefully

```java
package com.jdnbrothers.tlms.exception;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Handle 403 Forbidden responses
 * Called when user is authenticated but lacks required role/permission
 */
@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                      HttpServletResponse response,
                      AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        
        log.warn("Access denied for user: {}, path: {}", 
            request.getRemoteUser(), request.getRequestURI());
        
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        Map<String, Object> errorResponse = Map.of(
            "status", HttpStatus.FORBIDDEN.value(),
            "error", "FORBIDDEN",
            "message", "You don't have permission to access this resource",
            "timestamp", LocalDateTime.now(),
            "path", request.getRequestURI()
        );
        
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }
}
```

---

## 9. Testing Authorization

### Unit Tests for AuthorizationService

```java
package com.jdnbrothers.tlms.service.security;

import com.jdnbrothers.tlms.security.principal.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class AuthorizationServiceTest {

    @Autowired
    private AuthorizationService authService;

    private UserPrincipal adminUser;
    private UserPrincipal regularUser;

    @BeforeEach
    void setUp() {
        adminUser = UserPrincipal.builder()
            .id(1L)
            .username("admin")
            .roleNames(Set.of("ADMIN"))
            .build();

        regularUser = UserPrincipal.builder()
            .id(2L)
            .username("user")
            .roleNames(Set.of("USER"))
            .build();
    }

    @Test
    @DisplayName("isAdmin should return true for ADMIN role")
    @WithMockUser(roles = "ADMIN")
    void testIsAdminReturnsTrue() {
        // Arrange
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(adminUser);
        context.setAuthentication(auth);

        // Act
        boolean result = authService.isAdmin();

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("hasRole should return false for USER with ADMIN role check")
    @WithMockUser(roles = "USER")
    void testHasRoleReturnsFalseForWrongRole() {
        // Arrange
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(regularUser);
        context.setAuthentication(auth);

        // Act
        boolean result = authService.hasRole("ADMIN");

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("isCurrentUser should return true for same user ID")
    void testIsCurrentUserReturnsTrue() {
        // Arrange
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(regularUser);
        context.setAuthentication(auth);

        // Act
        boolean result = authService.isCurrentUser(2L);

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("isAdminOrOwner should return true for owner")
    void testIsAdminOrOwnerReturnsTrueForOwner() {
        // Arrange
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(regularUser);
        context.setAuthentication(auth);

        // Act
        boolean result = authService.isAdminOrOwner(2L); // regularUser.id = 2

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("isAdminOrOwner should return true for admin")
    void testIsAdminOrOwnerReturnsTrueForAdmin() {
        // Arrange
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(adminUser);
        context.setAuthentication(auth);

        // Act
        boolean result = authService.isAdminOrOwner(999L); // Different user

        // Assert
        assertTrue(result);
    }
}
```

### Integration Tests for Controllers

```java
package com.jdnbrothers.tlms.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    // ===== GET /api/users (Admin Only) =====

    @Test
    @DisplayName("GET /api/users should return 200 for admin")
    @WithMockUser(roles = "ADMIN")
    void testGetAllUsersAsAdmin() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    @DisplayName("GET /api/users should return 403 for regular user")
    @WithMockUser(roles = "USER")
    void testGetAllUsersAsUser() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isForbidden())
            .andDo(print());
    }

    @Test
    @DisplayName("GET /api/users should return 401 for unauthenticated")
    void testGetAllUsersUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isUnauthorized())
            .andDo(print());
    }

    // ===== GET /api/users/{id} (Admin OR Owner) =====

    @Test
    @DisplayName("GET /api/users/1 should return 200 for admin")
    @WithMockUser(username = "admin", roles = "ADMIN")
    void testGetUserAsAdmin() throws Exception {
        mockMvc.perform(get("/api/users/999"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    @DisplayName("GET /api/users/1 should return 200 for owner")
    @WithMockUser(username = "user1", roles = "USER")
    void testGetOwnUserProfile() throws Exception {
        // Assuming user ID 1 belongs to user1
        mockMvc.perform(get("/api/users/1"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    @DisplayName("GET /api/users/1 should return 403 for different user")
    @WithMockUser(username = "user2", roles = "USER")
    void testGetOtherUserProfileForbidden() throws Exception {
        // user2 trying to access user1's profile
        mockMvc.perform(get("/api/users/1"))
            .andExpect(status().isForbidden())
            .andDo(print());
    }

    // ===== DELETE /api/users/{id} (Admin Only) =====

    @Test
    @DisplayName("DELETE /api/users/1 should return 204 for admin")
    @WithMockUser(roles = "ADMIN")
    void testDeleteUserAsAdmin() throws Exception {
        mockMvc.perform(delete("/api/users/999"))
            .andExpect(status().isNoContent())
            .andDo(print());
    }

    @Test
    @DisplayName("DELETE /api/users/1 should return 403 for user")
    @WithMockUser(roles = "USER")
    void testDeleteUserAsUser() throws Exception {
        mockMvc.perform(delete("/api/users/999"))
            .andExpect(status().isForbidden())
            .andDo(print());
    }

    // ===== GET /api/users/me (Any Authenticated) =====

    @Test
    @DisplayName("GET /api/users/me should return 200 for authenticated user")
    @WithMockUser(roles = "USER")
    void testGetOwnProfileAuthenticated() throws Exception {
        mockMvc.perform(get("/api/users/me"))
            .andExpect(status().isOk())
            .andDo(print());
    }

    @Test
    @DisplayName("GET /api/users/me should return 401 for unauthenticated")
    void testGetOwnProfileUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/users/me"))
            .andExpect(status().isUnauthorized())
            .andDo(print());
    }
}
```

---

## 10. Common Authorization Patterns

### Pattern 1: Admin Panel (Admin Only)

```java
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")  // Applies to all methods
public class AdminController {

    @GetMapping("/dashboard")
    public ResponseEntity<?> getDashboard() { }

    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() { }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest req) { }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) { }
}
```

### Pattern 2: User Profile (Admin OR Owner)

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    @PreAuthorize("@authService.canViewUser(#id)")
    public ResponseEntity<?> getUser(@PathVariable Long id) { }

    @PutMapping("/{id}")
    @PreAuthorize("@authService.canEditUser(#id)")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody UpdateRequest req) { }

    @DeleteMapping("/{id}")
    @PreAuthorize("@authService.canDeleteUser(#id)")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) { }
}
```

### Pattern 3: Team Management (Team Lead OR Admin)

```java
@RestController
@RequestMapping("/api/teams/{teamId}")
public class TeamController {

    @GetMapping("/members")
    @PreAuthorize("@authService.isTeamMember(#teamId, authentication.principal.id) or hasRole('ADMIN')")
    public ResponseEntity<?> getMembers(@PathVariable Long teamId) { }

    @PostMapping("/members")
    @PreAuthorize("@authService.isTeamLead(#teamId, authentication.principal.id) or hasRole('ADMIN')")
    public ResponseEntity<?> addMember(@PathVariable Long teamId, @RequestBody AddMemberRequest req) { }

    @DeleteMapping("/members/{memberId}")
    @PreAuthorize("@authService.isTeamLead(#teamId, authentication.principal.id) or hasRole('ADMIN')")
    public ResponseEntity<?> removeMember(@PathVariable Long teamId, @PathVariable Long memberId) { }
}
```

### Pattern 4: Resource with Sharing Permissions

```java
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    /**
     * Can view: author, shared users, admin
     */
    @GetMapping("/{id}")
    @PreAuthorize("@authService.canViewDocument(#id)")
    public ResponseEntity<?> getDocument(@PathVariable Long id) { }

    /**
     * Can edit: author only, admin with override
     */
    @PutMapping("/{id}")
    @PreAuthorize("@authService.canEditDocument(#id)")
    public ResponseEntity<?> updateDocument(@PathVariable Long id, @RequestBody UpdateDocRequest req) { }

    /**
     * Can share: author, admin
     */
    @PostMapping("/{id}/share")
    @PreAuthorize("@authService.canShareDocument(#id)")
    public ResponseEntity<?> shareDocument(@PathVariable Long id, @RequestBody ShareRequest req) { }
}
```

---

## 11. Troubleshooting

### Issue: @PreAuthorize Not Working

```
// Symptom: Endpoint is accessible despite @PreAuthorize("hasRole('ADMIN')")

// Cause 1: @EnableMethodSecurity not in @Configuration class
@Configuration
@EnableMethodSecurity(prePostEnabled = true)  // ← Add this
public class SecurityConfig { }

// Cause 2: UserPrincipal not returned from UserDetailsService
public UserDetails loadUserByUsername(String username) {
    User user = userRepository.findByUsername(username).orElseThrow();
    return new UserPrincipal(...);  // ← Return UserPrincipal, not User
}

// Cause 3: Roles not prefixed with "ROLE_"
user.getAuthorities()  // Must return "ROLE_ADMIN", not "ADMIN"
```

### Issue: "User is Authenticated but Access Denied"

```
// This means:
// - User is logged in (401 not thrown)
// - But lacks required role/permission (403 thrown)

// Debug: Check @PreAuthorize expression and user roles
@PreAuthorize("hasRole('ADMIN')")  // User has ROLE_USER, not ROLE_ADMIN
public ResponseEntity<?> getData() { }

// Check user's actual roles:
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
auth.getAuthorities().forEach(a -> System.out.println(a.getAuthority()));
```

### Issue: AuthorizationService Bean Not Found

```
// Symptom: "Unknown bean 'authService'"

// Cause: AuthorizationService not a @Service or @Component
@Service  // ← Add this
public class AuthorizationService { }

// Also ensure it's in scanned packages:
@SpringBootApplication
@ComponentScan(basePackages = {"com.jdnbrothers.tlms"})
public class Application { }
```

---

## 12. Performance Considerations

### Avoid N+1 Queries in Authorization Checks

```java
// ❌ DON'T: Database query for each authorization check
@GetMapping("/users/{id}/teams")
@PreAuthorize("@authService.isTeamMember(#userId)")  // Query per request
public ResponseEntity<?> getUserTeams(@PathVariable Long userId) { }

// ✅ DO: Cache or pre-load in authentication
// In UserDetailsService:
public UserDetails loadUserByUsername(String username) {
    User user = userRepository.findByUsername(username)
        .orElseThrow();
    
    // Eagerly load related data
    Set<String> teamIds = teamRepository.findTeamIdsByUser(user.getId());
    
    return UserPrincipal.builder()
        // ...
        .cachedTeamIds(teamIds)  // Cache in principal
        .build();
}

// In AuthorizationService:
public boolean isTeamMember(Long teamId) {
    UserPrincipal user = getCurrentUser();
    return user.getCachedTeamIds().contains(teamId);  // No query
}
```

### Cache Authorization Results

```java
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    @Cacheable(value = "canEditResource", key = "#userId + '-' + #resourceId")
    public boolean canEditResource(Long userId, Long resourceId) {
        // Expensive check - result cached for 5 minutes
        return checkPermission(userId, resourceId);
    }

    @CacheEvict(value = "canEditResource", key = "#userId + '-' + #resourceId")
    public void invalidatePermissionCache(Long userId, Long resourceId) {
        // Call when permissions change
    }
}
```

---

## 13. Security Checklist

Before deploying, verify:

- [ ] All endpoints have `@PreAuthorize` or are explicitly public
- [ ] Admin endpoints cannot be accessed by regular users (test with both roles)
- [ ] Users cannot view/edit/delete others' data (without admin role)
- [ ] Admins cannot accidentally remove their own admin role
- [ ] Authorization checks happen on the backend, not just frontend
- [ ] Sensitive data is properly logged (user IDs in audit logs)
- [ ] Authorization failures are logged (for detection of attacks)
- [ ] All exceptions are caught and don't leak sensitive info
- [ ] JWT tokens expire and require refresh
- [ ] Password reset requires email verification
- [ ] Rate limiting on login endpoint (prevent brute force)
- [ ] CORS is properly configured (not allow all)
- [ ] CSRF is disabled (since using JWT) or properly configured

---

## 14. Quick Reference Table

| Annotation | Purpose | Example |
|-----------|---------|---------|
| `@PreAuthorize` | Check **before** method | `@PreAuthorize("hasRole('ADMIN')")` |
| `@PostAuthorize` | Check **after** method | `@PostAuthorize("returnObject.owner == principal.id")` |
| `@Secured` | Legacy role check | `@Secured("ROLE_ADMIN")` |
| `@RolesAllowed` | JSR-250 standard | `@RolesAllowed("ADMIN")` |
| `hasRole()` | Check single role | `hasRole('ADMIN')` |
| `hasAnyRole()` | Check multiple roles | `hasAnyRole('ADMIN', 'MANAGER')` |
| `isAuthenticated()` | Check if logged in | `isAuthenticated()` |
| `isAnonymous()` | Check if not logged in | `isAnonymous()` |
| `principal` | Get user principal | `principal.id`, `principal.username` |
| `authentication` | Get Authentication object | `authentication.name` |
| `#paramName` | Access method parameter | `#userId`, `#resourceId` |
| `@beanName.method()` | Call service method | `@authService.canEdit(#id)` |

---

## 15. Additional Resources

- [Spring Security Official Docs](https://spring.io/projects/spring-security)
- [Spring Security Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8949)

---

## FAQ

**Q: Should I use HTTP-level or method-level authorization?**  
A: Use both. HTTP-level for coarse rules (public vs. authenticated), method-level for fine-grained role/ownership checks.

**Q: How often should I test authorization?**  
A: Every time you add a protected endpoint. Aim for 80%+ code coverage of authorization logic.

**Q: Can I cache authorization results?**  
A: Yes, use `@Cacheable`. Invalidate when permissions change.

**Q: What if a user's role changes while they're logged in?**  
A: Their JWT token still has old roles until it expires. Use short token expiry (e.g., 15 mins) and refresh tokens.

**Q: Should I log authorization failures?**  
A: Yes. Log failed authorization attempts to detect attacks. Be careful not to log sensitive data.

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024 | Initial documentation |

---

**Document Owner**: Development Team  
**Last Updated**: [Current Date]  
**Review Cycle**: Quarterly