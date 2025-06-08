# Central Authentication System Client
# FastAPI application that integrates with auth-central-challange.vercel.app

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import httpx
import asyncio
from datetime import datetime, timedelta
import logging
import os
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
AUTH_BASE_URL = "https://auth-central-challange.vercel.app"
ACCESS_TOKEN_EXPIRE_MINUTES = 2
REFRESH_TOKEN_EXPIRE_MINUTES = 4

# Pydantic Models
class UserRegister(BaseModel):
    """User registration model"""
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    """User login model"""
    username: str
    password: str

class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    """Refresh token request model"""
    refresh_token: str

class UserInfo(BaseModel):
    """User information model"""
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool

# Token Manager Class
class TokenManager:
    """Manages access and refresh tokens with automatic refresh capability"""
    
    def __init__(self):
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.refresh_expires_at: Optional[datetime] = None
        self._http_client = httpx.AsyncClient()
    
    def set_tokens(self, access_token: str, refresh_token: str):
        """Set tokens and their expiration times"""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expires_at = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        self.refresh_expires_at = datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
        logger.info(f"Tokens set. Access expires at: {self.token_expires_at}, Refresh expires at: {self.refresh_expires_at}")
    
    def is_access_token_expired(self) -> bool:
        """Check if access token is expired or about to expire (30 seconds buffer)"""
        if not self.token_expires_at:
            return True
        return datetime.now() >= (self.token_expires_at - timedelta(seconds=30))
    
    def is_refresh_token_expired(self) -> bool:
        """Check if refresh token is expired"""
        if not self.refresh_expires_at:
            return True
        return datetime.now() >= self.refresh_expires_at
    
    async def refresh_access_token(self) -> bool:
        """Refresh the access token using the refresh token"""
        if not self.refresh_token or self.is_refresh_token_expired():
            logger.error("Refresh token is missing or expired")
            return False
        
        try:
            logger.info("Attempting to refresh access token...")
            
            # Try multiple possible refresh endpoints
            possible_endpoints = [
                f"{AUTH_BASE_URL}/refresh",
                f"{AUTH_BASE_URL}/auth/refresh",
                f"{AUTH_BASE_URL}/api/refresh",
                f"{AUTH_BASE_URL}/token/refresh"
            ]
            
            for endpoint in possible_endpoints:
                try:
                    response = await self._http_client.post(
                        endpoint,
                        json={"refresh_token": self.refresh_token},
                        headers={"Content-Type": "application/json"}
                    )
                    if response.status_code != 404:
                        break
                except:
                    continue
            else:
                response = await self._http_client.post(
                    f"{AUTH_BASE_URL}/auth/refresh",
                    json={"refresh_token": self.refresh_token},
                    headers={"Content-Type": "application/json"}
                )
            
            if response.status_code == 200:
                token_data = response.json()
                self.set_tokens(
                    access_token=token_data["access_token"],
                    refresh_token=token_data.get("refresh_token", self.refresh_token)
                )
                logger.info("Access token refreshed successfully")
                return True
            else:
                logger.error(f"Token refresh failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return False
    
    async def get_valid_access_token(self) -> Optional[str]:
        """Get a valid access token, refreshing if necessary"""
        if not self.access_token:
            logger.warning("No access token available")
            return None
        
        if self.is_access_token_expired():
            logger.info("Access token expired, attempting refresh...")
            if await self.refresh_access_token():
                return self.access_token
            else:
                logger.error("Failed to refresh access token")
                return None
        
        return self.access_token
    
    def clear_tokens(self):
        """Clear all tokens"""
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.refresh_expires_at = None
        logger.info("All tokens cleared")

# Global token manager instance
token_manager = TokenManager()

# Authentication Service
class AuthService:
    """Service for handling authentication operations"""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient()
    
    async def register_user(self, user_data: UserRegister) -> Dict[str, Any]:
        """Register a new user"""
        try:
            # Try multiple possible endpoints
            possible_endpoints = [
                f"{AUTH_BASE_URL}/register",
                f"{AUTH_BASE_URL}/auth/register",
                f"{AUTH_BASE_URL}/api/register"
            ]
            
            for endpoint in possible_endpoints:
                try:
                    response = await self.http_client.post(
                        endpoint,
                        json=user_data.dict(),
                        headers={"Content-Type": "application/json"}
                    )
                    if response.status_code != 404:
                        break
                except:
                    continue
            else:
                response = await self.http_client.post(
                    f"{AUTH_BASE_URL}/auth/register",
                    json=user_data.dict(),
                    headers={"Content-Type": "application/json"}
                )
            
            if response.status_code == 201 or response.status_code == 200:
                logger.info(f"Registration successful with status {response.status_code}")
                return response.json()
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Registration failed: {response.text}"
                )
                
        except httpx.RequestError as e:
            logger.error(f"Registration request failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )
    
    async def login_user(self, login_data: UserLogin) -> TokenResponse:
        """Login user and get tokens"""
        try:
            # Try multiple possible endpoints
            possible_endpoints = [
                f"{AUTH_BASE_URL}/login",
                f"{AUTH_BASE_URL}/auth/login", 
                f"{AUTH_BASE_URL}/api/login",
                f"{AUTH_BASE_URL}/token"
            ]
            
            response = None
            for endpoint in possible_endpoints:
                try:
                    logger.info(f"Trying login endpoint: {endpoint}")
                    response = await self.http_client.post(
                        endpoint,
                        json=login_data.dict(),
                        headers={"Content-Type": "application/json"}
                    )
                    if response.status_code != 404:
                        logger.info(f"Found working endpoint: {endpoint}")
                        break
                except Exception as e:
                    logger.warning(f"Failed to connect to {endpoint}: {str(e)}")
                    continue
            
            if not response:
                response = await self.http_client.post(
                    f"{AUTH_BASE_URL}/auth/login",
                    json=login_data.dict(),
                    headers={"Content-Type": "application/json"}
                )
            
            if response.status_code == 200:
                token_data = response.json()
                logger.info("Login successful, tokens received")
                
                # Store tokens in token manager
                token_manager.set_tokens(
                    access_token=token_data["access_token"],
                    refresh_token=token_data["refresh_token"]
                )
                
                return TokenResponse(**token_data)
            else:
                logger.error(f"Login failed: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Login failed: {response.text}"
                )
                
        except httpx.RequestError as e:
            logger.error(f"Login request failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )
    
    async def get_protected_data(self, access_token: str) -> Dict[str, Any]:
        """Get protected data using access token"""
        try:
            response = await self.http_client.get(
                f"{AUTH_BASE_URL}/protected",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Failed to get protected data: {response.text}"
                )
                
        except httpx.RequestError as e:
            logger.error(f"Protected data request failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )

# Global auth service instance
auth_service = AuthService()

# Security dependencies
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get current authenticated user"""
    token = credentials.credentials
    
    # Verify token with central auth service
    try:
        response = await auth_service.http_client.get(
            f"{AUTH_BASE_URL}/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable"
        )

# FastAPI app lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("🚀 Starting Central Authentication Client")
    yield
    # Cleanup
    await auth_service.http_client.aclose()
    await token_manager._http_client.aclose()
    logger.info("✅ Application shutdown complete")

# FastAPI Application
app = FastAPI(
    title="Central Authentication Client",
    description="FastAPI client for central authentication system integration",
    version="1.0.0",
    lifespan=lifespan
)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/debug/test-endpoints")
async def test_central_auth_endpoints():
    """Test which endpoints are available on the central auth service"""
    endpoints_to_test = [
        "/",
        "/docs", 
        "/openapi.json",
        "/auth/login",
        "/login",
        "/auth/register", 
        "/register",
        "/auth/refresh",
        "/refresh",
        "/protected", 
        "/auth/me",
        "/me"
    ]
    
    results = {}
    async with httpx.AsyncClient() as client:
        for endpoint in endpoints_to_test:
            try:
                url = f"{AUTH_BASE_URL}{endpoint}"
                response = await client.get(url, timeout=5.0)
                results[endpoint] = {
                    "status_code": response.status_code,
                    "accessible": response.status_code != 404
                }
            except Exception as e:
                results[endpoint] = {
                    "status_code": "error",
                    "error": str(e),
                    "accessible": False
                }
    
    return {
        "central_auth_url": AUTH_BASE_URL,
        "endpoint_results": results,
        "recommendation": "Use endpoints that return 200, 405, or other non-404 status codes"
    }

# Authentication endpoints
@app.post("/register", response_model=Dict[str, Any])
async def register(user_data: UserRegister):
    """Register a new user"""
    return await auth_service.register_user(user_data)

@app.post("/login", response_model=TokenResponse)
async def login(login_data: UserLogin):
    """Login user and get tokens"""
    return await auth_service.login_user(login_data)

@app.post("/logout")
async def logout():
    """Logout user by clearing tokens"""
    token_manager.clear_tokens()
    return {"message": "Successfully logged out"}

@app.get("/token/status")
async def token_status():
    """Get current token status"""
    return {
        "has_access_token": token_manager.access_token is not None,
        "has_refresh_token": token_manager.refresh_token is not None,
        "access_token_expired": token_manager.is_access_token_expired(),
        "refresh_token_expired": token_manager.is_refresh_token_expired(),
        "access_expires_at": token_manager.token_expires_at.isoformat() if token_manager.token_expires_at else None,
        "refresh_expires_at": token_manager.refresh_expires_at.isoformat() if token_manager.refresh_expires_at else None
    }

@app.post("/token/refresh")
async def refresh_token():
    """Manually refresh access token"""
    if await token_manager.refresh_access_token():
        return {"message": "Token refreshed successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to refresh token"
        )

# Protected endpoints
@app.get("/protected/data")
async def get_protected_data():
    """Get protected data with automatic token refresh"""
    access_token = await token_manager.get_valid_access_token()
    
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No valid access token available. Please login first."
        )
    
    return await auth_service.get_protected_data(access_token)

@app.get("/protected/profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile (requires valid token)"""
    return {
        "message": "Access granted to protected profile endpoint",
        "user": current_user,
        "timestamp": datetime.now().isoformat()
    }

# Demo endpoints for testing
@app.get("/demo/test-flow")
async def test_authentication_flow():
    """Test the complete authentication flow"""
    instructions = {
        "message": "Complete Authentication Flow Test",
        "steps": [
            "1. POST /register - Register a new user",
            "2. POST /login - Login with credentials",
            "3. GET /protected/data - Access protected data",
            "4. GET /token/status - Check token status",
            "5. Wait for token expiration or POST /token/refresh",
            "6. GET /protected/data - Test automatic refresh",
            "7. POST /logout - Clear tokens"
        ],
        "example_user": {
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepassword123",
            "full_name": "Test User"
        }
    }
    return instructions

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )