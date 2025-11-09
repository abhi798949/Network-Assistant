# rbac.py (Role-Based Access Control)
from functools import wraps
from flask import session, request, jsonify, render_template
from enum import Enum
from typing import Dict, List, Set
import hashlib
import secrets
from datetime import datetime, timedelta
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Permission(Enum):
    READ_DEVICES = "read_devices"
    WRITE_DEVICES = "write_devices"
    EXECUTE = "execute_commands"
    CONFIGURE = "configure_devices"
    MANAGE_USERS = "manage_users"
    VIEW_LOGS = "view_logs"
    MANAGE_ALERTS = "manage_alerts"
    VIEW_SECURITY = "view_security"
    VIEW_MONITORING = "view_monitoring"
    MANAGE_CONNECTIONS = "manage_connections"
    BACKUP = "backup"
    ACCESS_AUDIT = "access_audit"
    RESTORE = "restore"
    GOLDEN = "golden"
    VIEW = "view"
    UPLOAD = "upload"
    DOWNLOAD = "download"

class Role(Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"

class User:
    def __init__(self, username: str, password_hash: str, roles: List[Role]):
        self.username = username
        self.password_hash = password_hash
        self.roles = roles
        self.created_at = datetime.now()
        self.last_login = None
        self.failed_attempts = 0
        self.locked_until = None

class RoleManager:
    """Role-based access control manager"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.role_permissions = {
            Role.ADMIN: {
                Permission.READ_DEVICES, Permission.WRITE_DEVICES,
                Permission.EXECUTE, Permission.CONFIGURE,
                Permission.MANAGE_USERS, Permission.VIEW_LOGS, Permission.MANAGE_ALERTS,
                Permission.VIEW_MONITORING, Permission.MANAGE_CONNECTIONS, Permission.VIEW_SECURITY, Permission.BACKUP,
                Permission.ACCESS_AUDIT, Permission.RESTORE, Permission.GOLDEN, Permission.VIEW, Permission.UPLOAD, Permission.DOWNLOAD
            },
            Role.OPERATOR: {
                Permission.READ_DEVICES, Permission.EXECUTE, Permission.CONFIGURE, Permission.BACKUP,
                Permission.VIEW,
            },
            Role.VIEWER: {
                Permission.READ_DEVICES, Permission.VIEW_LOGS, Permission.VIEW,
            },
            Role.AUDITOR: {
                Permission.READ_DEVICES, Permission.VIEW_LOGS, Permission.EXECUTE, Permission.ACCESS_AUDIT, Permission.VIEW,
            }
        }
        
        # Create default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user"""
        admin_password = os.getenv("ADMIN_PASSWORD") or "admin123" # Fallback if none or empty
        self.create_user("admin", admin_password, [Role.ADMIN])
        print(f"Default admin created - Username: admin, Password: {admin_password}")
    
    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_value = password_hash.split(':')
            computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return computed_hash.hex() == hash_value
        except:
            return False
    
    def create_user(self, username: str, password: str, roles: List[Role]) -> bool:
        """Create a new user"""
        if username in self.users:
            return False
        
        password_hash = self.hash_password(password)
        self.users[username] = User(username, password_hash, roles)
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user"""
        user = self.users.get(username)
        if not user:
            return False
        
        # Check if account is locked
        if user.locked_until and datetime.now() < user.locked_until:
            return False
        
        if self.verify_password(password, user.password_hash):
            user.last_login = datetime.now()
            user.failed_attempts = 0
            user.locked_until = None
            return True
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.now() + timedelta(minutes=30)
            return False
    
    def has_permission(self, username: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        user = self.users.get(username)
        if not user:
            return False
        
        for role in user.roles:
            if permission in self.role_permissions.get(role, set()):
                return True
        return False
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                username = session.get('username')
                if not username or not self.has_permission(username, permission):
                    logging.warning(f"Access denied to {request.path} for user {username or 'anonymous'}: Missing {permission.value}")
                    if request.is_json or request.accept_mimetypes.best == 'application/json':
                        return jsonify({'error': 'Insufficient permissions'}), 403
                    return render_template('403.html'), 403
                return f(*args, **kwargs)
            return decorated_function
        return decorator


