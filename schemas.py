"""
Database Schemas for CollabLab (Option A)

Each Pydantic model represents a MongoDB collection.
The collection name is the lowercase of the class name by convention.

Collections we use:
- users
- projects
- collaboration_requests
- saved_projects
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Literal
from datetime import datetime


class Users(BaseModel):
    id: Optional[str] = Field(None, description="Document ID (Mongo ObjectId as string)")
    name: str
    email: str
    password_hash: Optional[str] = Field(None, description="BCrypt hash of password")
    provider: Literal["credentials", "google"] = "credentials"
    created_at: Optional[datetime] = None


class Project(BaseModel):
    id: Optional[str] = None
    owner_id: str
    title: str
    description: str
    skills_required: List[str] = []
    expected_contribution: Optional[str] = None
    duration: Optional[str] = None
    tags: List[str] = []
    visibility: Literal["public", "private"] = "public"
    created_at: Optional[datetime] = None


class CollaborationRequest(BaseModel):
    id: Optional[str] = None
    project_id: str
    applicant_id: str
    message: str
    portfolio_url: HttpUrl
    document_path: Optional[str] = None
    status: Literal["pending", "accepted", "rejected"] = "pending"
    created_at: Optional[datetime] = None


class SavedProject(BaseModel):
    id: Optional[str] = None
    user_id: str
    project_id: str
    created_at: Optional[datetime] = None
