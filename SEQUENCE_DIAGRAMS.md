# Sequence Diagrams - Authentication & User Management System

## 🔐 1. User Signup Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as AuthController
    participant Service as AuthService
    participant UserService as UsersService
    participant DB as MongoDB
    participant Email as EmailService
    participant Gmail as Gmail SMTP

    User->>Client: Fill signup form
    Client->>Controller: POST /auth/signup<br/>{name, email, password, role, etc}
    Controller->>Service: signup(createUserDto)
    Service->>UserService: create(createUserDto)
    
    UserService->>DB: findOne({email})
    DB-->>UserService: null (no existing user)
    
    UserService->>UserService: crypt password
    UserService->>DB: save(user with hashed password)
    DB-->>UserService: created user
    
    UserService->>Email: sendMail(email, subject, html)
    Email->>Gmail: Send welcome email
    Gmail-->>Email: Email sent
    Email-->>UserService: success
    
    UserService-->>Service: user (without password)
    Service-->>Controller: {user, message}
    Controller-->>Client: 201 Created<br/>{user, message}
    Client-->>User: "Account created! Check email"
```

---

## 🔑 2. User Login Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as AuthController
    participant Service as AuthService
    participant UserService as UsersService
    participant DB as MongoDB
    participant JWT as JwtService
    participant Email as EmailService
    participant Gmail as Gmail SMTP

    User->>Client: Enter email & password
    Client->>Controller: POST /auth/login<br/>{email, password}
    Controller->>Service: login(loginDto)
    
    Service->>Service: validateUser(email, password)
    Service->>UserService: findByEmail(email)
    UserService->>DB: findOne({email})
    DB-->>UserService: user document
    UserService-->>Service: user
    
    Service->>Service: bcrypt.compare(password, user.password)
    alt Password Invalid
        Service-->>Controller: UnauthorizedException
        Controller-->>Client: 401 Unauthorized
        Client-->>User: "Invalid credentials"
    end
    
    Service->>JWT: sign({userId, email, role}, {expiresIn: '15m'})
    JWT-->>Service: access_token
    
    Service->>Service: generateRefreshToken(userId)
    Service->>Service: crypto.randomBytes(64).toString('hex')
    Service->>DB: create RefreshToken<br/>{userId, token, expiresAt, isRevoked: false}
    DB-->>Service: saved refresh token
    Service-->>Service: refresh_token
    
    Service->>Email: sendMail(email, "Login Notification", html)
    Email->>Gmail: Send login notification
    Gmail-->>Email: Email sent
    
    Service-->>Controller: {access_token, refresh_token, user}
    Controller-->>Client: 200 OK<br/>{access_token, refresh_token, user}
    Client->>Client: Save tokens to localStorage
    Client-->>User: "Login successful"
```

---

## 🔄 3. Token Refresh Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as AuthController
    participant Service as AuthService
    participant DB as MongoDB
    participant UserService as UsersService
    participant JWT as JwtService

    User->>Client: Access token expires (15 min)
    Client->>Client: Detect 401 error
    Client->>Controller: POST /auth/refresh<br/>{refreshToken}
    Controller->>Service: refresh(refreshToken)
    
    Service->>DB: findOne({token, isRevoked: false})
    
    alt Token Not Found or Revoked
        DB-->>Service: null
        Service-->>Controller: UnauthorizedException
        Controller-->>Client: 401 Unauthorized
        Client-->>User: "Please login again"
    end
    
    DB-->>Service: storedToken
    
    Service->>Service: Check if expiresAt < now()
    alt Token Expired
        Service->>DB: findByIdAndDelete(tokenId)
        Service-->>Controller: UnauthorizedException
        Controller-->>Client: 401 Unauthorized
        Client-->>User: "Please login again"
    end
    
    Service->>UserService: findOne(storedToken.userId)
    UserService->>DB: findById(userId)
    DB-->>UserService: user
    UserService-->>Service: user
    
    Service->>JWT: sign({userId, email, role}, {expiresIn: '15m'})
    JWT-->>Service: newAccessToken
    
    Service->>Service: generateRefreshToken(userId)
    Service->>Service: crypto.randomBytes(64).toString('hex')
    Service->>DB: create new RefreshToken
    DB-->>Service: newRefreshToken
    
    Service->>DB: updateOne(oldTokenId, {isRevoked: true, replacedByToken})
    DB-->>Service: updated
    
    Service-->>Controller: {access_token, refresh_token}
    Controller-->>Client: 200 OK<br/>{access_token, refresh_token}
    Client->>Client: Replace old tokens
    Client-->>User: Continue using app
```

---

## 👤 4. Get Profile (Protected Route) Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as AuthController
    participant Guard as JwtAuthGuard
    participant Strategy as JwtStrategy
    participant JWT as JwtService
    participant Config as ConfigService

    User->>Client: Click "View Profile"
    Client->>Controller: GET /auth/profile<br/>Authorization: Bearer <token>
    Controller->>Guard: canActivate()
    Guard->>Strategy: validate(request)
    
    Strategy->>Strategy: Extract token from header
    Strategy->>JWT: verify(token, secret)
    
    alt Token Invalid/Expired
        JWT-->>Strategy: Error
        Strategy-->>Guard: UnauthorizedException
        Guard-->>Controller: 401 Unauthorized
        Controller-->>Client: 401 Unauthorized
        Client-->>User: "Please login"
    end
    
    JWT-->>Strategy: decoded payload {userId, email, role}
    Strategy->>Strategy: validate(payload)
    Strategy-->>Guard: {userId, email, role}
    Guard->>Guard: Attach to req.user
    Guard-->>Controller: true (allow access)
    
    Controller->>Controller: getProfile(@Request req)
    Controller-->>Client: 200 OK<br/>{user: req.user}
    Client-->>User: Display profile
```

---

## 📋 5. Get All Users (Role-Based) Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as UsersController
    participant JwtGuard as JwtAuthGuard
    participant RoleGuard as RolesGuard
    participant Service as UsersService
    participant DB as MongoDB

    User->>Client: Request users list
    Client->>Controller: GET /users<br/>Authorization: Bearer <token>
    
    Controller->>JwtGuard: canActivate()
    JwtGuard->>JwtGuard: Verify JWT token
    JwtGuard-->>Controller: req.user = {userId, email, role}
    
    Controller->>RoleGuard: canActivate()
    RoleGuard->>RoleGuard: Get required roles from @Roles decorator
    Note over RoleGuard: Required: [LANDLORD, LAWYER]
    RoleGuard->>RoleGuard: Check if req.user.role in requiredRoles
    
    alt User is TENANT
        RoleGuard-->>Controller: UnauthorizedException
        Controller-->>Client: 401 Unauthorized
        Client-->>User: "Access denied"
    end
    
    alt User is LANDLORD or LAWYER
        RoleGuard-->>Controller: true (allow access)
        Controller->>Service: findAll()
        Service->>DB: find().select('-password')
        DB-->>Service: users array (no passwords)
        Service-->>Controller: users
        Controller-->>Client: 200 OK<br/>[{user1}, {user2}, ...]
        Client-->>User: Display users list
    end
```

---

## 🔓 6. Logout Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as AuthController
    participant Guard as JwtAuthGuard
    participant Service as AuthService
    participant DB as MongoDB

    User->>Client: Click "Logout"
    Client->>Controller: POST /auth/logout<br/>Authorization: Bearer <token><br/>{refreshToken}
    
    Controller->>Guard: canActivate()
    Guard->>Guard: Verify access token
    Guard-->>Controller: req.user = {userId, email, role}
    
    Controller->>Service: logout(userId, refreshToken)
    Service->>DB: updateMany({userId, token},<br/>{isRevoked: true})
    DB-->>Service: updated
    Service-->>Controller: {message: "Logged out"}
    
    Controller-->>Client: 200 OK<br/>{message: "Logged out successfully"}
    Client->>Client: Delete tokens from localStorage
    Client->>Client: Redirect to login page
    Client-->>User: "You've been logged out"
```


## ✏️ 8. Update User Flow

```mermaid
sequenceDiagram
    actor User
    participant Client
    participant Controller as UsersController
    participant Guard as JwtAuthGuard
    participant Service as UsersService
    participant DB as MongoDB

    User->>Client: Edit profile form
    Client->>Controller: PATCH /users/:id<br/>Authorization: Bearer <token><br/>{name, phoneNumber, ...}
    
    Controller->>Guard: canActivate()
    Guard->>Guard: Verify JWT token
    Guard-->>Controller: req.user authenticated
    
    Controller->>Service: update(id, updateUserDto)
    
    alt Password being updated
        Service->>Service: crypt password
    end
    
    alt Email being changed
        Service->>DB: findOne({email, _id: {$ne: id}})
        alt Email already in use
            DB-->>Service: existing user
            Service-->>Controller: ConflictException
            Controller-->>Client: 409 Conflict
            Client-->>User: "Email already taken"
        end
    end
    
    Service->>DB: findByIdAndUpdate(id, updateData, {new: true})
    
    alt User not found
        DB-->>Service: null
        Service-->>Controller: NotFoundException
        Controller-->>Client: 404 Not Found
        Client-->>User: "User not found"
    end
    
    DB-->>Service: updated user
    Service->>Service: Remove password from response
    Service-->>Controller: user (without password)
    Controller-->>Client: 200 OK<br/>{updated user}
    Client-->>User: "Profile updated"
```

---

## 🗑️ 9. Delete User (Landlord Only) Flow

```mermaid
sequenceDiagram
    actor Landlord
    participant Client
    participant Controller as UsersController
    participant JwtGuard as JwtAuthGuard
    participant RoleGuard as RolesGuard
    participant Service as UsersService
    participant DB as MongoDB

    Landlord->>Client: Click "Delete User"
    Client->>Controller: DELETE /users/:id<br/>Authorization: Bearer <token>
    
    Controller->>JwtGuard: canActivate()
    JwtGuard->>JwtGuard: Verify JWT token
    JwtGuard-->>Controller: req.user = {userId, email, role}
    
    Controller->>RoleGuard: canActivate()
    RoleGuard->>RoleGuard: Check @Roles(LANDLORD)
    
    alt User is NOT Landlord
        RoleGuard-->>Controller: UnauthorizedException
        Controller-->>Client: 401 Unauthorized
        Client-->>Landlord: "Only landlords can delete users"
    end
    
    RoleGuard-->>Controller: true (is landlord)
    Controller->>Service: remove(id)
    Service->>DB: findByIdAndDelete(id)
    
    alt User not found
        DB-->>Service: null
        Service-->>Controller: NotFoundException
        Controller-->>Client: 404 Not Found
        Client-->>Landlord: "User not found"
    end
    
    DB-->>Service: deleted user
    Service-->>Controller: {message, id}
    Controller-->>Client: 200 OK<br/>{message: "User deleted", id}
    Client-->>Landlord: "User deleted successfully"
```

---

## 📧 10. Email Notification Flow (Background)

```mermaid
sequenceDiagram
    participant Service as AuthService/UsersService
    participant Email as EmailService
    participant Transporter as Nodemailer
    participant Gmail as Gmail SMTP
    participant User

    Service->>Email: sendMail(to, subject, html)
    Email->>Email: Get credentials from process.env
    Note over Email: GMAIL_USER, GMAIL_APP_PASS
    
    Email->>Transporter: createTransport({service: 'gmail', auth})
    Transporter-->>Email: transporter instance
    
    Email->>Transporter: sendMail({from, to, subject, html})
    Transporter->>Gmail: SMTP connection
    Gmail->>Gmail: Authenticate with app password
    
    alt Authentication Failed
        Gmail-->>Transporter: Auth error
        Transporter-->>Email: Error
        Email-->>Service: Error (logged, not thrown)
        Note over Service: Email failure doesn't<br/>block signup/login
    end
    
    Gmail->>Gmail: Queue email
    Gmail->>User: Email delivered
    User->>User: Check inbox
    
    Gmail-->>Transporter: Success
    Transporter-->>Email: {messageId}
    Email-->>Service: Success
```








