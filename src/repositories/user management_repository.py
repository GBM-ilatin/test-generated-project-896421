```python
# src/models/user.py
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from pydantic import EmailStr


class UserBase(SQLModel):
    """Base user model with common fields."""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    is_active: bool = Field(default=True)


class User(UserBase, table=True):
    """User database model."""
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default=None)


class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(min_length=8)


class UserUpdate(SQLModel):
    """User update model."""
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(default=None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8)


class UserRead(UserBase):
    """User read model."""
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
```

```python
# src/repositories/user_repository.py
from abc import ABC, abstractmethod
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from src.models.user import User, UserCreate, UserUpdate


class UserRepositoryInterface(ABC):
    """Abstract interface for user repository."""
    
    @abstractmethod
    async def create(self, user_data: UserCreate) -> User:
        """Create a new user."""
        pass
    
    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        pass
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        pass
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        pass
    
    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """Get all users with pagination."""
        pass
    
    @abstractmethod
    async def update(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user by ID."""
        pass
    
    @abstractmethod
    async def delete(self, user_id: int) -> bool:
        """Delete user by ID."""
        pass
    
    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email."""
        pass
    
    @abstractmethod
    async def exists_by_username(self, username: str) -> bool:
        """Check if user exists by username."""
        pass


class UserRepository(UserRepositoryInterface):
    """SQLAlchemy implementation of user repository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, user_data: UserCreate) -> User:
        """
        Create a new user.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user instance
            
        Raises:
            IntegrityError: If user with email/username already exists
        """
        try:
            user = User(**user_data.model_dump(exclude={"password"}), 
                       password_hash=user_data.password)  # In real app, hash the password
            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)
            return user
        except IntegrityError as e:
            await self.session.rollback()
            raise e
    
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User instance or None if not found
        """
        statement = select(User).where(User.id == user_id)
        result = await self.session.exec(statement)
        return result.first()
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User instance or None if not found
        """
        statement = select(User).where(User.email == email)
        result = await self.session.exec(statement)
        return result.first()
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User instance or None if not found
        """
        statement = select(User).where(User.username == username)
        result = await self.session.exec(statement)
        return result.first()
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of user instances
        """
        statement = select(User).offset(skip).limit(limit)
        result = await self.session.exec(statement)
        return result.all()
    
    async def update(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """
        Update user by ID.
        
        Args:
            user_id: User ID
            user_data: User update data
            
        Returns:
            Updated user instance or None if not found
        """
        try:
            update_data = user_data.model_dump(exclude_unset=True)
            if not update_data:
                return await self.get_by_id(user_id)
            
            if "password" in update_data:
                update_data["password_hash"] = update_data.pop("password")
            
            update_data["updated_at"] = datetime.utcnow()
            
            statement = (
                update(User)
                .where(User.id == user_id)
                .values(**update_data)
                .returning(User)
            )
            
            result = await self.session.exec(statement)
            updated_user = result.first()
            
            if updated_user:
                await self.session.commit()
                await self.session.refresh(updated_user)
            
            return updated_user
        except IntegrityError as e:
            await self.session.rollback()
            raise e
    
    async def delete(self, user_id: int) -> bool:
        """
        Delete user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            True if user was deleted, False if not found
        """
        statement = delete(User).where(User.id == user_id)
        result = await self.session.exec(statement)
        await self.session.commit()
        return result.rowcount > 0
    
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if user exists by email.
        
        Args:
            email: User email
            
        Returns:
            True if user exists, False otherwise
        """
        statement = select(User.id).where(User.email == email)
        result = await self.session.exec(statement)
        return result.first() is not None
    
    async def exists_by_username(self, username: str) -> bool:
        """
        Check if user exists by username.
        
        Args:
            username: Username
            
        Returns:
            True if user exists, False otherwise
        """
        statement = select(User.id).where(User.username == username)
        result = await self.session.exec(statement)
        return result.first() is not None
```

```python
# src/services/user_service.py
from typing import List, Optional
from datetime import datetime
from src.models.user import User, UserCreate, UserUpdate, UserRead
from src.repositories.user_repository import UserRepositoryInterface
from src.exceptions import UserNotFoundError, UserAlreadyExistsError


class UserService:
    """Service layer for user operations."""
    
    def __init__(self, user_repository: UserRepositoryInterface):
        self.user_repository = user_repository
    
    async def create_user(self, user_data: UserCreate) -> UserRead:
        """
        Create a new user.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user data
            
        Raises:
            UserAlreadyExistsError: If user with email/username already exists
        """
        # Check if user already exists
        if await self.user_repository.exists_by_email(user_data.email):
            raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")
        
        if await self.user_repository.exists_by_username(user_data.username):
            raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")
        
        try:
            user = await self.user_repository.create(user_data)
            return UserRead.model_validate(user)
        except Exception as e:
            raise e
    
    async def get_user_by_id(self, user_id: int) -> UserRead:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User data
            
        Raises:
            UserNotFoundError: If user not found
        """
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        return UserRead.model_validate(user)
    
    async def get_user_by_email(self, email: str) -> UserRead:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User data
            
        Raises:
            UserNotFoundError: If user not found
        """
        user = await self.user_repository.get_by_email(email)
        if not user:
            raise UserNotFoundError(f"User with email {email} not found")
        
        return UserRead.model_validate(user)
    
    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[UserRead]:
        """
        Get all users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of user data
        """
        users = await self.user_repository.get_all(skip=skip, limit=limit)
        return [UserRead.model_validate(user) for user in users]
    
    async def update_user(self, user_id: int, user_data: UserUpdate) -> UserRead:
        """
        Update user by ID.
        
        Args:
            user_id: User ID
            user_data: User update data
            
        Returns:
            Updated user data
            
        Raises:
            UserNotFoundError: If user not found
            UserAlreadyExistsError: If email/username already taken by another user
        """
        # Check if user exists
        existing_user = await self.user_repository.get_by_id(user_id)
        if not existing_user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        # Check for email conflicts
        if user_data.email and user_data.email != existing_user.email:
            if await self.user_repository.exists_by_email(user_data.email):
                raise UserAlreadyExistsError(f"Email {user_data.email} already taken")
        
        # Check for username conflicts
        if user_data.username and user_data.username != existing_user.username:
            if await self.user_repository.exists_by_username(user_data.username):
                raise UserAlreadyExistsError(f"Username {user_data.username} already taken")
        
        try:
            updated_user = await self.user_repository.update(user_id, user_data)
            return UserRead.model_validate(updated_user)
        except Exception as e:
            raise e
    
    async def delete_user(self, user_id: int) -> bool:
        """
        Delete user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            True if user was deleted
            
        Raises:
            UserNotFoundError: If user not found
        """
        if not await self.user_repository.get_by_id(user_id):
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        return await self.user_repository.delete(user_id)
```

```python
# src/exceptions.py
class UserNotFoundError(Exception):
    """Raised when user is not found."""
    pass


class UserAlreadyExistsError(Exception):
    """Raised when user already exists."""
    pass
```

```python
# src/dependencies.py
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from src.repositories.user_repository import UserRepository, UserRepositoryInterface
from src.services.user_service import UserService

# Database configuration
DATABASE_URL = "postgresql+asyncpg://user:password@localhost/dbname"
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def get_user_repository(session: AsyncSession) -> UserRepositoryInterface:
    """Dependency to get user repository."""
    return UserRepository(session)


def get_user_service(user_repository: UserRepositoryInterface) -> UserService:
    """Dependency to get user service."""
    return UserService(user_repository)
```