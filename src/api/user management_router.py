```python
# src/models/user.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8, max_length=100)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int
    page: int
    size: int

# src/services/user_service.py
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from src.models.user import User, UserCreate, UserUpdate
from passlib.context import CryptContext
from typing import Optional, List
from fastapi import HTTPException, status

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserService:
    def __init__(self, db: Session):
        self.db = db
    
    def get_password_hash(self, password: str) -> str:
        return pwd_context.hash(password)
    
    def create_user(self, user_data: UserCreate) -> User:
        try:
            hashed_password = self.get_password_hash(user_data.password)
            db_user = User(
                email=user_data.email,
                username=user_data.username,
                full_name=user_data.full_name,
                hashed_password=hashed_password
            )
            self.db.add(db_user)
            self.db.commit()
            self.db.refresh(db_user)
            return db_user
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email or username already exists"
            )
    
    def get_user(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        return self.db.query(User).filter(User.username == username).first()
    
    def get_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        return self.db.query(User).offset(skip).limit(limit).all()
    
    def get_users_count(self) -> int:
        return self.db.query(User).count()
    
    def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        db_user = self.get_user(user_id)
        if not db_user:
            return None
        
        try:
            update_data = user_data.model_dump(exclude_unset=True)
            for field, value in update_data.items():
                setattr(db_user, field, value)
            
            self.db.commit()
            self.db.refresh(db_user)
            return db_user
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email or username already exists"
            )
    
    def delete_user(self, user_id: int) -> bool:
        db_user = self.get_user(user_id)
        if not db_user:
            return False
        
        self.db.delete(db_user)
        self.db.commit()
        return True

# src/api/users.py
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List
from src.models.user import UserCreate, UserUpdate, UserResponse, UserListResponse
from src.services.user_service import UserService
from src.database import get_db

router = APIRouter(prefix="/users", tags=["users"])

def get_user_service(db: Session = Depends(get_db)) -> UserService:
    return UserService(db)

@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user",
    description="Create a new user with email, username, full name, and password"
)
async def create_user(
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    """
    Create a new user with the following information:
    
    - **email**: Valid email address (must be unique)
    - **username**: Username between 3-50 characters (must be unique)
    - **full_name**: Full name between 1-100 characters
    - **password**: Password between 8-100 characters
    """
    return user_service.create_user(user_data)

@router.get(
    "/",
    response_model=UserListResponse,
    summary="Get all users",
    description="Retrieve a paginated list of all users"
)
async def get_users(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(10, ge=1, le=100, description="Number of users per page"),
    user_service: UserService = Depends(get_user_service)
):
    """
    Get a paginated list of users.
    
    - **page**: Page number (starts from 1)
    - **size**: Number of users per page (1-100)
    """
    skip = (page - 1) * size
    users = user_service.get_users(skip=skip, limit=size)
    total = user_service.get_users_count()
    
    return UserListResponse(
        users=users,
        total=total,
        page=page,
        size=size
    )

@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="Retrieve a specific user by their ID"
)
async def get_user(
    user_id: int,
    user_service: UserService = Depends(get_user_service)
):
    """
    Get a specific user by ID.
    
    - **user_id**: The ID of the user to retrieve
    """
    user = user_service.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user",
    description="Update an existing user's information"
)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    user_service: UserService = Depends(get_user_service)
):
    """
    Update an existing user's information.
    
    - **user_id**: The ID of the user to update
    - **email**: New email address (optional)
    - **username**: New username (optional)
    - **full_name**: New full name (optional)
    - **is_active**: New active status (optional)
    """
    user = user_service.update_user(user_id, user_data)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    description="Delete a user by their ID"
)
async def delete_user(
    user_id: int,
    user_service: UserService = Depends(get_user_service)
):
    """
    Delete a user by their ID.
    
    - **user_id**: The ID of the user to delete
    """
    success = user_service.delete_user(user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

@router.get(
    "/email/{email}",
    response_model=UserResponse,
    summary="Get user by email",
    description="Retrieve a specific user by their email address"
)
async def get_user_by_email(
    email: str,
    user_service: UserService = Depends(get_user_service)
):
    """
    Get a specific user by email address.
    
    - **email**: The email address of the user to retrieve
    """
    user = user_service.get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.get(
    "/username/{username}",
    response_model=UserResponse,
    summary="Get user by username",
    description="Retrieve a specific user by their username"
)
async def get_user_by_username(
    username: str,
    user_service: UserService = Depends(get_user_service)
):
    """
    Get a specific user by username.
    
    - **username**: The username of the user to retrieve
    """
    user = user_service.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user
```