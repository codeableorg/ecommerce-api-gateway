# Keycloak Integration Guide for Microservices

## Overview

This guide demonstrates how to integrate Keycloak with a microservices architecture to implement secure, centralized authentication. We'll transform an insecure system where `userId` is passed in request bodies into a JWT-based authentication system.

### Current Security Issues

The existing system has critical security vulnerabilities:

- No authentication mechanism
- `userId` sent in request bodies (easily spoofed)
- Any client can impersonate any user
- No access control between users

### Target Architecture

After integration:

- JWT tokens for user authentication
- Centralized user management via Keycloak
- Secure user identification extracted from validated tokens
- Stateless authentication across microservices

---

## Step 1: Keycloak Setup

### 1.1: Create Docker Compose for Keycloak

Create `docker-compose-keycloak.yml`:

```yaml
version: "3.8"
services:
  keycloak-postgres:
    image: postgres:15
    container_name: keycloak-postgres
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
    volumes:
      - keycloak_postgres_data:/var/lib/postgresql/data
    ports:
      - "5433:5432"

  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    container_name: keycloak
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://keycloak-postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8090:8080"
    depends_on:
      - keycloak-postgres
    command: start-dev

volumes:
  keycloak_postgres_data:
```

Key points:

- Port 8090 to avoid conflicts with our services
- `start-dev` mode for development environment
- Separate database for Keycloak

### 1.2: Start Keycloak

```bash
docker-compose -f docker-compose-keycloak.yml up -d
```

Wait for startup and visit http://localhost:8090. Login with admin/admin.

### 1.3: Create Realm and Client

1. **Create Realm:**

   - Click "Create Realm"
   - Name: `ecommerce`
   - Save

2. **Create Client for API Gateway:**

   - Go to Clients → Create Client
   - Client ID: `api-gateway`
   - Client Type: `OpenID Connect`
   - Save

3. **Configure Client:**

   - Access Type: `confidential`
   - Valid Redirect URIs: `http://localhost:8080/*`
   - Web Origins: `http://localhost:8080`
   - Save

4. **Get Client Secret:**
   - Go to Credentials tab
   - Copy the secret (we'll need this)

### 1.4: Create Test User

1. Go to Users → Add User
2. Username: `testuser`
3. Email: `test@example.com`
4. Save
5. Go to Credentials tab
6. Set password: `password123`
7. Turn off "Temporary"

---

## Step 2: Configure API Gateway

### 2.1: Add Dependencies

Update `api-gateway/pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 2.2: Configure OAuth2 in API Gateway

Update `api-gateway/src/main/resources/application.yml`:

```yaml
server:
  port: 8080

spring:
  application:
    name: api-gateway
  cloud:
    gateway:
      routes:
        # Public routes (no auth required)
        - id: user-service-public
          uri: http://localhost:8081
          predicates:
            - Path=/api/users/register
          filters:
            - StripPrefix=0

        # Protected routes (auth required)
        - id: user-service
          uri: http://localhost:8081
          predicates:
            - Path=/api/users/**
          filters:
            - TokenRelay

        - id: product-service
          uri: http://localhost:8082
          predicates:
            - Path=/api/products/**
          filters:
            - TokenRelay

        - id: inventory-service
          uri: http://localhost:8083
          predicates:
            - Path=/api/inventory/**
          filters:
            - TokenRelay

        - id: order-service
          uri: http://localhost:8084
          predicates:
            - Path=/api/orders/**
          filters:
            - TokenRelay

  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: api-gateway
            client-secret: YOUR_CLIENT_SECRET_HERE
            scope: openid,profile,email
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:8080/login/oauth2/code/keycloak
        provider:
          keycloak:
            authorization-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/auth
            token-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/token
            user-info-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/userinfo
            jwk-set-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/certs
            user-name-attribute: preferred_username
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/certs

logging:
  level:
    org.springframework.cloud.gateway: DEBUG
    org.springframework.security: DEBUG
```

**Key Points:**

- `TokenRelay` filter forwards JWT to downstream services
- Public vs Protected routes configuration
- OAuth2 client vs resource server configuration

### Step 3.3: Create Security Configuration

Create `api-gateway/src/main/java/com/ecommerce/api_gateway/config/SecurityConfig.java`:

```java
package com.ecommerce.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(exchanges -> exchanges
                // Public endpoints
                .pathMatchers("/api/users/register").permitAll()
                .pathMatchers("/actuator/**").permitAll()
                // All other endpoints require authentication
                .anyExchange().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2.loginPage("/oauth2/authorization/keycloak"))
            .oauth2ResourceServer(oauth2 -> oauth2.jwt())
            .csrf().disable()
            .build();
    }
}
```

**Key Points:**

- Reactive security for Spring Cloud Gateway
- Path-based authorization rules
- OAuth2 login configuration

---

## Phase 4: Secure Individual Microservices

### Step 4.1: Add Dependencies to Each Service

**Teaching Point:** "Each microservice needs to validate JWT tokens independently"

Add to `user-service/pom.xml`, `product-service/pom.xml`, etc.:

```xml
		<!-- OAuth2 Resource Server for JWT validation -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-config</artifactId>
		</dependency>
```

### Step 4.2: Configure JWT Validation

Add to each service's `application.yml`:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8090/realms/ecommerce/protocol/openid-connect/certs
```

### Step 4.3: Create Security Configuration for Services

Create in each service `config/SecurityConfig.java`:

```java
package com.ecommerce.user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Security configuration for User Service.
 *
 * This configuration:
 * 1. Validates JWT tokens from Keycloak
 * 2. Protects all endpoints except public ones
 * 3. Supports reactive WebFlux (non-blocking)
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            // Disable CSRF for stateless JWT authentication
            .csrf(csrf -> csrf.disable())

            // Configure authorization rules
            .authorizeExchange(exchanges -> exchanges
                // Public endpoints (no authentication required)
                .pathMatchers("/api/v1/users/register").permitAll()
                .pathMatchers("/actuator/health").permitAll()

                // All other endpoints require authentication
                .anyExchange().authenticated()
            )

            // Configure OAuth2 Resource Server for JWT validation
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {
                    // Keycloak will validate the JWT signature using JWKS endpoint
                    // Default configuration will use the jwk-set-uri from application.yml
                })
            )

            .build();
    }
}
```

- Stateless session management
- JWT validation on each request

---

## Step 5: Testing the Integration

### 5.1: Start All Services

```bash
# Terminal 1: API Gateway
cd api-gateway && mvn spring-boot:run

# Terminal 2: User Service
cd user-service && mvn spring-boot:run
```

### 5.2: Test Authentication Flow

1. **Try accessing protected endpoint (should fail):**

```bash
curl http://localhost:8080/api/users
# Should return 401 Unauthorized
```

2. **Get access token:**

```bash
curl -X POST http://localhost:8090/realms/ecommerce/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=api-gateway" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=password123"
```

3. **Use token to access protected endpoint:**

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8080/api/users
```

### 5.3: Web Browser Test

1. Visit: `http://localhost:8080/api/users`
2. You'll be redirected to Keycloak login
3. Login with testuser/password123
4. You'll be redirected back with access to the API

---

## Step 6: Secure User Identification

### 6.1: Remove userId from Request Bodies

The critical security improvement is eliminating `userId` from request bodies and extracting it from JWT tokens instead.

**Before (Insecure):**

```java
@PostMapping
public Mono<OrderDto> createOrder(@RequestBody CreateOrderRequest request) {
    // SECURITY ISSUE: userId comes from untrusted client!
    return orderService.createOrder(request.getUserId(), request.getItems())
        .map(orderMapper::toDto);
}
```

**After (Secure):**

```java
@PostMapping
public Mono<OrderDto> createOrder(
    @RequestBody CreateOrderRequest request,
    JwtAuthenticationToken token) {

    // User ID extracted from verified JWT token!
    String userId = token.getName();
    return orderService.createOrder(userId, request.getItems())
        .map(orderMapper::toDto);
}

@GetMapping
public Flux<OrderDto> getUserOrders(JwtAuthenticationToken token) {
    // Users can only see their own orders!
    String userId = token.getName();
    return orderService.getOrdersByUserId(userId)
        .map(orderMapper::toDto);
}
```

### 6.2: Update Request DTOs

Remove userId field from request DTOs:

```java
public class CreateOrderRequest {
    // Remove this field - userId now comes from JWT!
    // private Long userId;

    private List<OrderItemRequest> items;

    // getters and setters for items only
}
```

### 6.3: User Linking Strategy

**Current Approach: Username Mapping**

We connect Keycloak users to database users using the username field:

```java
String username = jwtUtils.getCurrentUsername(token); // "testuser"
return userService.getUserByUsername(username);
```

**Important:** Users must be created in both places:

1. Database user via API endpoint
2. Keycloak user via admin panel (manual)

In production, the user creation endpoint should create users in both systems automatically.

### 6.4: Update User Controller

Create self-service endpoints in UserController:

```java
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @GetMapping("/me")
    public Mono<UserDto> getCurrentUser(JwtAuthenticationToken token) {
        String username = jwtUtils.getCurrentUsername(token);
        return userService.getUserByUsername(username)
            .map(UserDto::fromEntity);
    }

    @PutMapping("/me")
    public Mono<UserDto> updateCurrentUser(
        @RequestBody UserDto userDto,
        JwtAuthenticationToken token) {
        String username = jwtUtils.getCurrentUsername(token);
        return userService.getUserByUsername(username)
            .flatMap(existingUser -> {
                userDto.setId(existingUser.getId());
                return userService.updateUser(UserDto.toEntity(userDto))
                    .map(UserDto::fromEntity);
            });
    }

    @GetMapping("/me/token-info")
    public Mono<Map<String, Object>> getTokenInfo(JwtAuthenticationToken token) {
        return Mono.just(Map.of(
            "userId", jwtUtils.getCurrentUserId(token),
            "username", jwtUtils.getCurrentUsername(token),
            "email", jwtUtils.getUserEmail(token),
            "fullName", jwtUtils.getUserFullName(token),
            "allAttributes", jwtUtils.getAllTokenAttributes(token)
        ));
    }
}
```

### Step 6.5: Extract User Information Utility

**Create a utility class for JWT handling:**

````java
@Component
public class JwtUtils {

    public String getCurrentUserId(JwtAuthenticationToken token) {
        return token.getName();
    }

    public String getCurrentUsername(JwtAuthenticationToken token) {
        return token.getName();
    }

    public String getUserEmail(JwtAuthenticationToken token) {
        return (String) token.getTokenAttributes().get("email");
    }

    public boolean hasRole(JwtAuthenticationToken token, String role) {
        return token.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_" + role));
    }

    public Map<String, Object> getAllTokenAttributes(JwtAuthenticationToken token) {
        return token.getTokenAttributes();
    }

    public String getUserFullName(JwtAuthenticationToken token) {
        return (String) token.getTokenAttributes().get("name");
    }
}

---

## Step 6: Frontend Integration

### 6.1: Update API Calls

**Before (Insecure):**
```javascript
// Frontend could send any userId
const createOrder = async (userId, items) => {
  const response = await fetch('/api/orders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, items })
  });
};
```

**After (Secure):**

```javascript
// JWT token identifies the user
const createOrder = async (items) => {
  const response = await fetch("/api/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getAccessToken()}`,
    },
    body: JSON.stringify({ items }),
  });
};
```

---

## Step 7: Testing the Security

### 7.1: Verify Security Improvements

**Before Keycloak (Vulnerable):**

```bash
# This worked before - security issue!
curl -X POST http://localhost:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"userId": 999, "items": [{"productId": 1, "quantity": 1}]}'
```

**After Keycloak (Secure):**

```bash
# This now fails with 401 Unauthorized
curl -X POST http://localhost:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"items": [{"productId": 1, "quantity": 1}]}'

# Must use valid JWT token:
curl -X POST http://localhost:8080/api/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"items": [{"productId": 1, "quantity": 1}]}'
```

### Step 8.2: Verify User Isolation

**Teaching Point:** "Users can only see their own data"

```bash
# Get token for user1
TOKEN1=$(curl -s -X POST http://localhost:8090/realms/ecommerce/protocol/openid-connect/token \
  -d "client_id=api-gateway&client_secret=$CLIENT_SECRET&grant_type=password&username=user1&password=password123" | jq -r .access_token)

# Get token for user2
TOKEN2=$(curl -s -X POST http://localhost:8090/realms/ecommerce/protocol/openid-connect/token \
  -d "client_id=api-gateway&client_secret=$CLIENT_SECRET&grant_type=password&username=user2&password=password123" | jq -r .access_token)

# user1 creates an order
curl -X POST http://localhost:8080/api/orders \
  -H "Authorization: Bearer $TOKEN1" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"productId": 1, "quantity": 1}]}'

# user2 cannot see user1's orders!
curl -H "Authorization: Bearer $TOKEN2" http://localhost:8080/api/orders
# Only returns user2's orders, not user1's
```

---

## Phase 9: Production Considerations

### Security Best Practices

**Token Management:**

```yaml
# In Keycloak realm settings
accessTokenLifespan: 300 # 5 minutes
refreshTokenMaxReuse: 0 # Single use refresh tokens
```

**HTTPS Configuration:**

```yaml
# All URLs should use HTTPS in production
spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            authorization-uri: https://keycloak.yourdomain.com/realms/ecommerce/protocol/openid-connect/auth
```

**Monitoring and Logging:**

```java
@Component
public class JwtAuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationSuccessHandler.class);

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        logger.info("User {} authenticated successfully", event.getAuthentication().getName());
    }
}
```

---

## Summary

### What We Achieved

- **Eliminated Security Vulnerabilities:** No more user impersonation via request bodies
- **Centralized Authentication:** Single source of truth for user management
- **Stateless Architecture:** JWT tokens, no server-side sessions
- **User Isolation:** Each user can only access their own data
- **Industry Standards:** OAuth2 and OpenID Connect compliance
- **Microservices Ready:** Each service validates tokens independently

### Before vs After Comparison

| Aspect          | Before (Insecure)        | After (Keycloak)          |
| --------------- | ------------------------ | ------------------------- |
| User ID         | Sent in request body     | Extracted from JWT        |
| Authentication  | None                     | JWT tokens                |
| Authorization   | None                     | JWT-based                 |
| User Isolation  | Any user can access data | Users see only their data |
| Impersonation   | Trivial to fake userId   | Cryptographically secure  |

## Next Steps

1. **Practice:** Add a new microservice and secure it
2. **User Management:** Connect user creation to Keycloak Admin API
3. **Explore:** Look into Keycloak's admin API
4. **Extend:** Add social login (Google, GitHub)
5. **Monitor:** Set up logging and metrics for authentication
6. **Deploy:** Learn about Keycloak clustering for production

## Troubleshooting

**Token Validation Fails:**
- Check JWT signature and issuer
- Verify clock synchronization
- Confirm JWK Set URI accessibility

**Redirect Loops:**
- Verify redirect URIs in Keycloak client
- Check CORS configuration
- Ensure proper session handling

**Service Communication Issues:**
- Verify TokenRelay filter in gateway
- Check network connectivity between services
- Confirm JWT format and claims
````
