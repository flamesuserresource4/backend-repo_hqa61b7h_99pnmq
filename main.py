import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError
from bson import ObjectId

from database import db, create_document, get_documents

# Environment & Security
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="CollabLab API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "iat": int(datetime.now(tz=timezone.utc).timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthUser(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None


async def get_current_user(authorization: Optional[str] = None) -> AuthUser:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            raise ValueError("Invalid scheme")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id or not email:
            raise ValueError("Invalid token payload")
        user = db["users"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return AuthUser(id=str(user["_id"]), email=user.get("email"), name=user.get("name"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Auth endpoints
class SignUpRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignUpRequest):
    existing = db["users"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "provider": "credentials",
        "created_at": datetime.now(timezone.utc),
    }
    user_id = db["users"].insert_one(user_doc).inserted_id
    token = create_token(str(user_id), payload.email)
    return TokenResponse(access_token=token)


class SignInRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/signin", response_model=TokenResponse)
def signin(payload: SignInRequest):
    user = db["users"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(user["_id"]), user["email"]) 
    return TokenResponse(access_token=token)


# Project models
class ProjectIn(BaseModel):
    title: str
    description: str
    skills_required: List[str] = []
    expected_contribution: Optional[str] = None
    duration: Optional[str] = None
    tags: List[str] = []
    visibility: str = "public"


class ProjectOut(ProjectIn):
    id: str
    owner_id: str
    created_at: datetime


# CRUD Projects
@app.post("/projects", response_model=ProjectOut)
def create_project(payload: ProjectIn, user: AuthUser = Depends(get_current_user)):
    doc = {
        **payload.model_dump(),
        "owner_id": user.id,
        "created_at": datetime.now(timezone.utc),
    }
    inserted = db["projects"].insert_one(doc)
    return ProjectOut(id=str(inserted.inserted_id), owner_id=user.id, created_at=doc["created_at"], **payload.model_dump())


@app.get("/projects", response_model=List[ProjectOut])
def list_projects(q: Optional[str] = None, tag: Optional[str] = None):
    query = {"visibility": "public"}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"tags": {"$elemMatch": {"$regex": q, "$options": "i"}}},
        ]
    if tag:
        query.setdefault("tags", {"$in": [tag]})
    cursor = db["projects"].find(query).sort("created_at", -1)
    items = []
    for p in cursor:
        items.append(
            ProjectOut(
                id=str(p["_id"]),
                owner_id=p["owner_id"],
                created_at=p["created_at"],
                title=p["title"],
                description=p["description"],
                skills_required=p.get("skills_required", []),
                expected_contribution=p.get("expected_contribution"),
                duration=p.get("duration"),
                tags=p.get("tags", []),
                visibility=p.get("visibility", "public"),
            )
        )
    return items


@app.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str):
    p = db["projects"].find_one({"_id": ObjectId(project_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut(
        id=str(p["_id"]),
        owner_id=p["owner_id"],
        created_at=p["created_at"],
        title=p["title"],
        description=p["description"],
        skills_required=p.get("skills_required", []),
        expected_contribution=p.get("expected_contribution"),
        duration=p.get("duration"),
        tags=p.get("tags", []),
        visibility=p.get("visibility", "public"),
    )


@app.put("/projects/{project_id}", response_model=ProjectOut)
def update_project(project_id: str, payload: ProjectIn, user: AuthUser = Depends(get_current_user)):
    p = db["projects"].find_one({"_id": ObjectId(project_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if p["owner_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    update = {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}
    db["projects"].update_one({"_id": ObjectId(project_id)}, {"$set": update})
    p = db["projects"].find_one({"_id": ObjectId(project_id)})
    return ProjectOut(
        id=str(p["_id"]),
        owner_id=p["owner_id"],
        created_at=p["created_at"],
        title=p["title"],
        description=p["description"],
        skills_required=p.get("skills_required", []),
        expected_contribution=p.get("expected_contribution"),
        duration=p.get("duration"),
        tags=p.get("tags", []),
        visibility=p.get("visibility", "public"),
    )


@app.delete("/projects/{project_id}")
def delete_project(project_id: str, user: AuthUser = Depends(get_current_user)):
    p = db["projects"].find_one({"_id": ObjectId(project_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if p["owner_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    db["projects"].delete_one({"_id": ObjectId(project_id)})
    # also clean up saved and collaboration requests
    db["savedproject"].delete_many({"project_id": project_id})
    db["collaborationrequest"].delete_many({"project_id": project_id})
    return {"ok": True}


# Saved projects
@app.post("/projects/{project_id}/save")
def save_project(project_id: str, user: AuthUser = Depends(get_current_user)):
    exists = db["savedproject"].find_one({"user_id": user.id, "project_id": project_id})
    if exists:
        return {"saved": True}
    db["savedproject"].insert_one({"user_id": user.id, "project_id": project_id, "created_at": datetime.now(timezone.utc)})
    return {"saved": True}


@app.get("/me/saved", response_model=List[ProjectOut])
def my_saved(user: AuthUser = Depends(get_current_user)):
    saved = list(db["savedproject"].find({"user_id": user.id}))
    ids = [ObjectId(s["project_id"]) for s in saved]
    projects = db["projects"].find({"_id": {"$in": ids}})
    items = []
    for p in projects:
        items.append(
            ProjectOut(
                id=str(p["_id"]),
                owner_id=p["owner_id"],
                created_at=p["created_at"],
                title=p["title"],
                description=p["description"],
                skills_required=p.get("skills_required", []),
                expected_contribution=p.get("expected_contribution"),
                duration=p.get("duration"),
                tags=p.get("tags", []),
                visibility=p.get("visibility", "public"),
            )
        )
    return items


# Collaboration Requests (with file upload)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/projects/{project_id}/apply")
async def apply_to_project(
    project_id: str,
    message: str = Form(...),
    portfolio_url: str = Form(...),
    document: UploadFile = File(...),
    user: AuthUser = Depends(get_current_user),
):
    project = db["projects"].find_one({"_id": ObjectId(project_id)})
    if not project or project.get("visibility", "public") == "private":
        raise HTTPException(status_code=404, detail="Project not found")

    # Save document privately (backend-only path)
    safe_name = f"{str(ObjectId())}_{document.filename}"
    path = os.path.join(UPLOAD_DIR, safe_name)
    content = await document.read()
    with open(path, "wb") as f:
        f.write(content)

    rec = {
        "project_id": project_id,
        "applicant_id": user.id,
        "message": message,
        "portfolio_url": portfolio_url,
        "document_path": path,
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
    }
    db["collaborationrequest"].insert_one(rec)
    return {"ok": True}


class RequestOut(BaseModel):
    id: str
    project_id: str
    applicant_id: str
    message: str
    portfolio_url: str
    status: str
    created_at: datetime


@app.get("/owner/projects/{project_id}/requests", response_model=List[RequestOut])
async def list_requests(project_id: str, user: AuthUser = Depends(get_current_user)):
    p = db["projects"].find_one({"_id": ObjectId(project_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if p["owner_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    items = []
    for r in db["collaborationrequest"].find({"project_id": project_id}).sort("created_at", -1):
        items.append(
            RequestOut(
                id=str(r["_id"]),
                project_id=r["project_id"],
                applicant_id=r["applicant_id"],
                message=r.get("message", ""),
                portfolio_url=r.get("portfolio_url", ""),
                status=r.get("status", "pending"),
                created_at=r["created_at"],
            )
        )
    return items


@app.get("/owner/requests/{request_id}/document")
async def download_document(request_id: str, user: AuthUser = Depends(get_current_user)):
    r = db["collaborationrequest"].find_one({"_id": ObjectId(request_id)})
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    p = db["projects"].find_one({"_id": ObjectId(r["project_id"])})
    if not p or p["owner_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    path = r.get("document_path")
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    filename = os.path.basename(path)
    return FileResponse(path, filename=filename)


class StatusUpdate(BaseModel):
    status: str


@app.post("/owner/requests/{request_id}/status")
async def update_status(request_id: str, payload: StatusUpdate, user: AuthUser = Depends(get_current_user)):
    r = db["collaborationrequest"].find_one({"_id": ObjectId(request_id)})
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    p = db["projects"].find_one({"_id": ObjectId(r["project_id"])})
    if not p or p["owner_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if payload.status not in ["pending", "accepted", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    db["collaborationrequest"].update_one({"_id": ObjectId(request_id)}, {"$set": {"status": payload.status}})
    return {"ok": True}


# Basic profile
class ProfileUpdate(BaseModel):
    name: Optional[str] = None


@app.get("/me")
async def me(user: AuthUser = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "name": user.name}


@app.post("/me")
async def update_me(payload: ProfileUpdate, user: AuthUser = Depends(get_current_user)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if update:
        db["users"].update_one({"_id": ObjectId(user.id)}, {"$set": update})
    u = db["users"].find_one({"_id": ObjectId(user.id)})
    return {"id": user.id, "email": u.get("email"), "name": u.get("name")}


@app.get("/")
def read_root():
    return {"message": "CollabLab API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
