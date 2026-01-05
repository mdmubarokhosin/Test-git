/**
 * Comprehensive Authentication Module
 * Handles user registration, login, logout, and role management
 * Version: 1.0.0
 * Created: 2026-01-05
 */

class AuthenticationModule {
  constructor(config = {}) {
    this.config = {
      tokenKey: config.tokenKey || 'auth_token',
      userKey: config.userKey || 'current_user',
      apiEndpoint: config.apiEndpoint || '/api/auth',
      tokenExpiration: config.tokenExpiration || 3600, // 1 hour in seconds
      maxLoginAttempts: config.maxLoginAttempts || 5,
      lockoutDuration: config.lockoutDuration || 900000, // 15 minutes in ms
      ...config
    };

    this.currentUser = null;
    this.token = null;
    this.loginAttempts = {};
    this.lockedAccounts = new Set();
    this.sessionTimers = {};
    this.rolePermissions = this._initializeRoles();

    this._restoreSession();
    this._setupSessionMonitoring();
  }

  /**
   * Initialize role-based permissions
   * @private
   */
  _initializeRoles() {
    return {
      admin: {
        permissions: ['read', 'write', 'delete', 'manage_users', 'manage_roles'],
        level: 3,
        description: 'Full system access'
      },
      moderator: {
        permissions: ['read', 'write', 'delete', 'manage_comments'],
        level: 2,
        description: 'Content moderation access'
      },
      user: {
        permissions: ['read', 'write'],
        level: 1,
        description: 'Standard user access'
      },
      guest: {
        permissions: ['read'],
        level: 0,
        description: 'Limited read-only access'
      }
    };
  }

  /**
   * User Registration
   * @param {Object} userData - User data for registration
   * @returns {Promise<Object>} Registration result
   */
  async register(userData) {
    try {
      // Validate input
      this._validateRegistrationData(userData);

      // Check if email already exists
      if (await this._emailExists(userData.email)) {
        throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
      }

      // Validate password strength
      const passwordValidation = this._validatePassword(userData.password);
      if (!passwordValidation.isValid) {
        throw new AuthError(passwordValidation.message, 'WEAK_PASSWORD', 400);
      }

      // Prepare user object
      const newUser = {
        id: this._generateUserId(),
        email: userData.email.toLowerCase(),
        username: userData.username,
        firstName: userData.firstName || '',
        lastName: userData.lastName || '',
        passwordHash: await this._hashPassword(userData.password),
        role: userData.role || 'user',
        createdAt: new Date().toISOString(),
        isActive: true,
        emailVerified: false,
        lastLogin: null,
        metadata: userData.metadata || {}
      };

      // Validate role
      if (!this._isValidRole(newUser.role)) {
        throw new AuthError('Invalid role specified', 'INVALID_ROLE', 400);
      }

      // Simulate API call
      const response = await this._apiCall('POST', '/register', newUser);

      // Log registration event
      this._logEvent('USER_REGISTERED', { userId: newUser.id, email: newUser.email });

      return {
        success: true,
        message: 'Registration successful. Please verify your email.',
        user: this._sanitizeUser(newUser),
        requiresEmailVerification: true
      };

    } catch (error) {
      this._handleError(error, 'REGISTRATION_FAILED');
      throw error;
    }
  }

  /**
   * User Login
   * @param {string} email - User email
   * @param {string} password - User password
   * @param {boolean} rememberMe - Keep user logged in
   * @returns {Promise<Object>} Login result
   */
  async login(email, password, rememberMe = false) {
    try {
      // Validate input
      if (!email || !password) {
        throw new AuthError('Email and password are required', 'MISSING_CREDENTIALS', 400);
      }

      const normalizedEmail = email.toLowerCase();

      // Check if account is locked
      if (this.lockedAccounts.has(normalizedEmail)) {
        throw new AuthError('Account temporarily locked due to multiple failed login attempts', 'ACCOUNT_LOCKED', 429);
      }

      // Attempt authentication
      const user = await this._authenticateUser(normalizedEmail, password);

      if (!user) {
        this._recordFailedLogin(normalizedEmail);
        throw new AuthError('Invalid email or password', 'INVALID_CREDENTIALS', 401);
      }

      // Check if user is active
      if (!user.isActive) {
        throw new AuthError('This account has been disabled', 'ACCOUNT_INACTIVE', 403);
      }

      // Generate token
      const token = this._generateToken(user, rememberMe);

      // Store session
      this.currentUser = user;
      this.token = token;
      this._storeSession(user, token, rememberMe);

      // Reset login attempts
      delete this.loginAttempts[normalizedEmail];

      // Update last login
      await this._updateLastLogin(user.id);

      // Log login event
      this._logEvent('USER_LOGIN', { userId: user.id, email: user.email, rememberMe });

      // Setup session timeout
      this._setupSessionTimeout(rememberMe);

      return {
        success: true,
        message: 'Login successful',
        user: this._sanitizeUser(user),
        token: token,
        expiresIn: this.config.tokenExpiration
      };

    } catch (error) {
      this._handleError(error, 'LOGIN_FAILED');
      throw error;
    }
  }

  /**
   * User Logout
   * @returns {Promise<Object>} Logout result
   */
  async logout() {
    try {
      if (!this.currentUser) {
        throw new AuthError('No user is currently logged in', 'NO_ACTIVE_SESSION', 400);
      }

      const userId = this.currentUser.id;
      const email = this.currentUser.email;

      // Notify server of logout
      await this._apiCall('POST', '/logout', { userId, token: this.token });

      // Clear session timers
      this._clearSessionTimers();

      // Clear stored session
      this._clearSession();

      // Clear memory
      this.currentUser = null;
      this.token = null;

      // Log logout event
      this._logEvent('USER_LOGOUT', { userId, email });

      return {
        success: true,
        message: 'Logout successful'
      };

    } catch (error) {
      // Even if there's an error, clear the session locally
      this._clearSession();
      this.currentUser = null;
      this.token = null;
      this._handleError(error, 'LOGOUT_FAILED');
      throw error;
    }
  }

  /**
   * Check if user has specific permission
   * @param {string} permission - Permission to check
   * @returns {boolean} Has permission
   */
  hasPermission(permission) {
    if (!this.currentUser) {
      return false;
    }

    const role = this.rolePermissions[this.currentUser.role];
    if (!role) {
      return false;
    }

    return role.permissions.includes(permission);
  }

  /**
   * Check if user has specific role
   * @param {string} role - Role to check
   * @returns {boolean} Has role
   */
  hasRole(role) {
    if (!this.currentUser) {
      return false;
    }

    return this.currentUser.role === role;
  }

  /**
   * Check if user has any of the given roles
   * @param {Array<string>} roles - Roles to check
   * @returns {boolean} Has any role
   */
  hasAnyRole(roles) {
    if (!this.currentUser || !Array.isArray(roles)) {
      return false;
    }

    return roles.includes(this.currentUser.role);
  }

  /**
   * Get user role level
   * @returns {number} Role level
   */
  getRoleLevel() {
    if (!this.currentUser) {
      return -1;
    }

    const role = this.rolePermissions[this.currentUser.role];
    return role ? role.level : -1;
  }

  /**
   * Update user role
   * @param {string} userId - User ID
   * @param {string} newRole - New role
   * @returns {Promise<Object>} Update result
   */
  async updateUserRole(userId, newRole) {
    try {
      // Check permission
      if (!this.hasPermission('manage_roles')) {
        throw new AuthError('You do not have permission to manage roles', 'PERMISSION_DENIED', 403);
      }

      // Validate role
      if (!this._isValidRole(newRole)) {
        throw new AuthError('Invalid role specified', 'INVALID_ROLE', 400);
      }

      // Prevent downgrading self
      if (userId === this.currentUser.id && newRole === 'guest') {
        throw new AuthError('Cannot downgrade your own role to guest', 'INVALID_OPERATION', 400);
      }

      // Update role
      const response = await this._apiCall('PUT', `/users/${userId}/role`, { role: newRole });

      // Update local user if it's the current user
      if (userId === this.currentUser.id) {
        this.currentUser.role = newRole;
        this._storeSession(this.currentUser, this.token);
      }

      // Log role change
      this._logEvent('ROLE_UPDATED', { userId, newRole, updatedBy: this.currentUser.id });

      return {
        success: true,
        message: `User role updated to ${newRole}`,
        user: response.user
      };

    } catch (error) {
      this._handleError(error, 'ROLE_UPDATE_FAILED');
      throw error;
    }
  }

  /**
   * Get current user
   * @returns {Object|null} Current user or null
   */
  getCurrentUser() {
    return this.currentUser ? this._sanitizeUser(this.currentUser) : null;
  }

  /**
   * Check if user is authenticated
   * @returns {boolean} Is authenticated
   */
  isAuthenticated() {
    return !!this.currentUser && !!this.token && !this._isTokenExpired();
  }

  /**
   * Refresh authentication token
   * @returns {Promise<Object>} New token
   */
  async refreshToken() {
    try {
      if (!this.currentUser || !this.token) {
        throw new AuthError('No active session to refresh', 'NO_ACTIVE_SESSION', 401);
      }

      const response = await this._apiCall('POST', '/refresh-token', { token: this.token });

      this.token = response.token;
      this._storeSession(this.currentUser, this.token);

      // Reset session timeout
      this._setupSessionTimeout(false);

      this._logEvent('TOKEN_REFRESHED', { userId: this.currentUser.id });

      return {
        success: true,
        token: this.token,
        expiresIn: this.config.tokenExpiration
      };

    } catch (error) {
      this._handleError(error, 'TOKEN_REFRESH_FAILED');
      // Clear session if token refresh fails
      await this.logout().catch(() => {});
      throw error;
    }
  }

  /**
   * Change user password
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<Object>} Change result
   */
  async changePassword(currentPassword, newPassword) {
    try {
      if (!this.currentUser) {
        throw new AuthError('No user is currently logged in', 'NO_ACTIVE_SESSION', 400);
      }

      if (!currentPassword || !newPassword) {
        throw new AuthError('Current and new passwords are required', 'MISSING_CREDENTIALS', 400);
      }

      // Validate new password strength
      const passwordValidation = this._validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        throw new AuthError(passwordValidation.message, 'WEAK_PASSWORD', 400);
      }

      // Verify current password
      const verified = await this._verifyPassword(currentPassword, this.currentUser.passwordHash);
      if (!verified) {
        throw new AuthError('Current password is incorrect', 'INVALID_PASSWORD', 401);
      }

      // Update password
      const newPasswordHash = await this._hashPassword(newPassword);
      await this._apiCall('PUT', `/users/${this.currentUser.id}/password`, {
        passwordHash: newPasswordHash
      });

      // Log password change
      this._logEvent('PASSWORD_CHANGED', { userId: this.currentUser.id });

      return {
        success: true,
        message: 'Password changed successfully'
      };

    } catch (error) {
      this._handleError(error, 'PASSWORD_CHANGE_FAILED');
      throw error;
    }
  }

  /**
   * Request password reset
   * @param {string} email - User email
   * @returns {Promise<Object>} Request result
   */
  async requestPasswordReset(email) {
    try {
      if (!email) {
        throw new AuthError('Email is required', 'MISSING_EMAIL', 400);
      }

      const normalizedEmail = email.toLowerCase();

      // Check if email exists (without revealing if it does)
      await this._apiCall('POST', '/password-reset-request', { email: normalizedEmail });

      this._logEvent('PASSWORD_RESET_REQUESTED', { email: normalizedEmail });

      return {
        success: true,
        message: 'If an account exists with this email, a password reset link has been sent'
      };

    } catch (error) {
      this._handleError(error, 'PASSWORD_RESET_REQUEST_FAILED');
      throw error;
    }
  }

  /**
   * Reset password with token
   * @param {string} resetToken - Reset token
   * @param {string} newPassword - New password
   * @returns {Promise<Object>} Reset result
   */
  async resetPasswordWithToken(resetToken, newPassword) {
    try {
      if (!resetToken || !newPassword) {
        throw new AuthError('Reset token and new password are required', 'MISSING_CREDENTIALS', 400);
      }

      // Validate password strength
      const passwordValidation = this._validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        throw new AuthError(passwordValidation.message, 'WEAK_PASSWORD', 400);
      }

      const newPasswordHash = await this._hashPassword(newPassword);

      await this._apiCall('POST', '/password-reset', {
        token: resetToken,
        passwordHash: newPasswordHash
      });

      this._logEvent('PASSWORD_RESET_COMPLETED', { token: resetToken.substring(0, 10) + '...' });

      return {
        success: true,
        message: 'Password reset successfully'
      };

    } catch (error) {
      this._handleError(error, 'PASSWORD_RESET_FAILED');
      throw error;
    }
  }

  /**
   * Get all available roles
   * @returns {Object} Available roles
   */
  getAvailableRoles() {
    return this.rolePermissions;
  }

  /**
   * Get permissions for a specific role
   * @param {string} role - Role name
   * @returns {Array<string>} Role permissions
   */
  getRolePermissions(role) {
    const roleData = this.rolePermissions[role];
    return roleData ? roleData.permissions : [];
  }

  // ============ PRIVATE METHODS ============

  /**
   * Validate registration data
   * @private
   */
  _validateRegistrationData(data) {
    if (!data.email || !data.username || !data.password) {
      throw new AuthError('Email, username, and password are required', 'MISSING_REQUIRED_FIELDS', 400);
    }

    if (!this._isValidEmail(data.email)) {
      throw new AuthError('Invalid email format', 'INVALID_EMAIL', 400);
    }

    if (data.username.length < 3 || data.username.length > 30) {
      throw new AuthError('Username must be between 3 and 30 characters', 'INVALID_USERNAME', 400);
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(data.username)) {
      throw new AuthError('Username can only contain letters, numbers, underscores, and hyphens', 'INVALID_USERNAME_FORMAT', 400);
    }
  }

  /**
   * Validate password strength
   * @private
   */
  _validatePassword(password) {
    if (password.length < 8) {
      return { isValid: false, message: 'Password must be at least 8 characters long' };
    }

    if (!/[A-Z]/.test(password)) {
      return { isValid: false, message: 'Password must contain at least one uppercase letter' };
    }

    if (!/[a-z]/.test(password)) {
      return { isValid: false, message: 'Password must contain at least one lowercase letter' };
    }

    if (!/[0-9]/.test(password)) {
      return { isValid: false, message: 'Password must contain at least one number' };
    }

    if (!/[!@#$%^&*]/.test(password)) {
      return { isValid: false, message: 'Password must contain at least one special character (!@#$%^&*)' };
    }

    return { isValid: true, message: 'Password is strong' };
  }

  /**
   * Validate email format
   * @private
   */
  _isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Check if role is valid
   * @private
   */
  _isValidRole(role) {
    return role in this.rolePermissions;
  }

  /**
   * Hash password (simulated - use bcrypt in production)
   * @private
   */
  async _hashPassword(password) {
    // In production, use bcrypt.hash(password, 10)
    return 'hashed_' + btoa(password);
  }

  /**
   * Verify password
   * @private
   */
  async _verifyPassword(password, hash) {
    // In production, use bcrypt.compare(password, hash)
    return 'hashed_' + btoa(password) === hash;
  }

  /**
   * Generate JWT-like token
   * @private
   */
  _generateToken(user, rememberMe = false) {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const expiresIn = rememberMe ? this.config.tokenExpiration * 7 : this.config.tokenExpiration;
    const payload = btoa(JSON.stringify({
      sub: user.id,
      email: user.email,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn
    }));
    const signature = btoa('signature');

    return `${header}.${payload}.${signature}`;
  }

  /**
   * Check if token is expired
   * @private
   */
  _isTokenExpired() {
    if (!this.token) return true;

    try {
      const parts = this.token.split('.');
      if (parts.length !== 3) return true;

      const payload = JSON.parse(atob(parts[1]));
      return payload.exp * 1000 < Date.now();
    } catch (error) {
      return true;
    }
  }

  /**
   * Authenticate user credentials
   * @private
   */
  async _authenticateUser(email, password) {
    // Simulate API call to verify credentials
    const response = await this._apiCall('POST', '/authenticate', { email, password });
    return response.user || null;
  }

  /**
   * Check if email exists
   * @private
   */
  async _emailExists(email) {
    try {
      await this._apiCall('GET', `/check-email?email=${encodeURIComponent(email)}`);
      return true;
    } catch (error) {
      if (error.status === 404) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Update last login timestamp
   * @private
   */
  async _updateLastLogin(userId) {
    try {
      await this._apiCall('PUT', `/users/${userId}/last-login`, { lastLogin: new Date().toISOString() });
    } catch (error) {
      // Log but don't throw
      console.warn('Failed to update last login:', error);
    }
  }

  /**
   * Record failed login attempt
   * @private
   */
  _recordFailedLogin(email) {
    this.loginAttempts[email] = (this.loginAttempts[email] || 0) + 1;

    if (this.loginAttempts[email] >= this.config.maxLoginAttempts) {
      this.lockedAccounts.add(email);
      setTimeout(() => {
        this.lockedAccounts.delete(email);
        delete this.loginAttempts[email];
      }, this.config.lockoutDuration);
    }
  }

  /**
   * Store session in localStorage
   * @private
   */
  _storeSession(user, token, rememberMe = false) {
    try {
      const sessionData = {
        user: user,
        token: token,
        timestamp: Date.now(),
        rememberMe: rememberMe
      };

      sessionStorage.setItem(this.config.userKey, JSON.stringify(user));
      sessionStorage.setItem(this.config.tokenKey, token);

      if (rememberMe) {
        localStorage.setItem(this.config.userKey, JSON.stringify(user));
        localStorage.setItem(this.config.tokenKey, token);
      }
    } catch (error) {
      console.warn('Failed to store session:', error);
    }
  }

  /**
   * Restore session from storage
   * @private
   */
  _restoreSession() {
    try {
      let user = null;
      let token = null;

      // Try sessionStorage first
      const sessionUser = sessionStorage.getItem(this.config.userKey);
      const sessionToken = sessionStorage.getItem(this.config.tokenKey);

      // Try localStorage if sessionStorage is empty
      const localUser = localStorage.getItem(this.config.userKey);
      const localToken = localStorage.getItem(this.config.tokenKey);

      if (sessionUser && sessionToken) {
        user = JSON.parse(sessionUser);
        token = sessionToken;
      } else if (localUser && localToken) {
        user = JSON.parse(localUser);
        token = localToken;
      }

      if (user && token && !this._isTokenExpired()) {
        this.currentUser = user;
        this.token = token;
      } else {
        this._clearSession();
      }
    } catch (error) {
      console.warn('Failed to restore session:', error);
      this._clearSession();
    }
  }

  /**
   * Clear session from storage
   * @private
   */
  _clearSession() {
    try {
      sessionStorage.removeItem(this.config.userKey);
      sessionStorage.removeItem(this.config.tokenKey);
      localStorage.removeItem(this.config.userKey);
      localStorage.removeItem(this.config.tokenKey);
    } catch (error) {
      console.warn('Failed to clear session:', error);
    }
  }

  /**
   * Setup session timeout
   * @private
   */
  _setupSessionTimeout(rememberMe = false) {
    this._clearSessionTimers();

    const timeoutDuration = rememberMe
      ? this.config.tokenExpiration * 7 * 1000
      : this.config.tokenExpiration * 1000;

    const timeoutId = setTimeout(() => {
      this.logout().catch(() => {
        console.warn('Session expired');
      });
    }, timeoutDuration);

    this.sessionTimers.timeout = timeoutId;
  }

  /**
   * Setup session monitoring
   * @private
   */
  _setupSessionMonitoring() {
    // Monitor for idle time
    if (typeof window !== 'undefined') {
      const idleTimeout = 30 * 60 * 1000; // 30 minutes
      let idleTimer = null;

      const resetIdleTimer = () => {
        if (idleTimer) clearTimeout(idleTimer);

        if (this.isAuthenticated()) {
          idleTimer = setTimeout(() => {
            console.warn('Session idle timeout');
            this.logout().catch(() => {});
          }, idleTimeout);
        }
      };

      // Track user activity
      ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
        window.addEventListener(event, resetIdleTimer, true);
      });

      this.sessionTimers.idle = idleTimer;
    }
  }

  /**
   * Clear all session timers
   * @private
   */
  _clearSessionTimers() {
    Object.values(this.sessionTimers).forEach(timerId => {
      if (timerId) clearTimeout(timerId);
    });
    this.sessionTimers = {};
  }

  /**
   * Sanitize user object (remove sensitive data)
   * @private
   */
  _sanitizeUser(user) {
    const { passwordHash, ...sanitized } = user;
    return sanitized;
  }

  /**
   * Simulate API call
   * @private
   */
  async _apiCall(method, endpoint, data = null) {
    try {
      // In production, use fetch or axios
      // This is a mock implementation
      console.log(`API ${method} ${this.config.apiEndpoint}${endpoint}`, data);

      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            success: true,
            user: data,
            token: data?.token || null
          });
        }, 100);
      });
    } catch (error) {
      throw new AuthError('API call failed', 'API_ERROR', 500);
    }
  }

  /**
   * Log event
   * @private
   */
  _logEvent(eventType, data = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType: eventType,
      data: data,
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'N/A'
    };

    console.log('[AUTH EVENT]', logEntry);

    // Store logs in localStorage for debugging
    try {
      const logs = JSON.parse(localStorage.getItem('auth_logs') || '[]');
      logs.push(logEntry);
      // Keep only last 100 logs
      if (logs.length > 100) logs.shift();
      localStorage.setItem('auth_logs', JSON.stringify(logs));
    } catch (error) {
      console.warn('Failed to log event:', error);
    }
  }

  /**
   * Handle errors with logging
   * @private
   */
  _handleError(error, context = '') {
    const errorLog = {
      timestamp: new Date().toISOString(),
      context: context,
      error: {
        message: error.message,
        code: error.code,
        status: error.status
      }
    };

    console.error('[AUTH ERROR]', errorLog);

    // Store error logs
    try {
      const logs = JSON.parse(localStorage.getItem('auth_error_logs') || '[]');
      logs.push(errorLog);
      if (logs.length > 50) logs.shift();
      localStorage.setItem('auth_error_logs', JSON.stringify(logs));
    } catch (err) {
      console.warn('Failed to log error:', err);
    }
  }

  /**
   * Generate unique user ID
   * @private
   */
  _generateUserId() {
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}

/**
 * Custom Authentication Error Class
 */
class AuthError extends Error {
  constructor(message, code = 'AUTH_ERROR', status = 400) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Export module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AuthenticationModule, AuthError };
}
