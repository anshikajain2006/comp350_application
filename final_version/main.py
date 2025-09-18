from __future__ import annotations
from fastapi import FastAPI, Request, Response, HTTPException, status, Cookie, Depends, Query, File
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, Annotated, List
import hmac
import secrets
import os

import auth_module as auth
import storage_module as storage
import particle_module as particles

# SQL Configuration
DATABASE_FILE = "pim.db"

app = FastAPI()

# CORS configuration for frontend
origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files - make sure this works
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static", html=True), name="static")

# Initialize database - both storage and particles modules handle their own initialization
storage.init_database(DATABASE_FILE)
particles.init_particles_db(DATABASE_FILE)

# Pydantic models for requests
class Credentials(BaseModel):
    username: str
    password: str

class ParticleCreate(BaseModel):
    title: str
    body: str

class ParticleUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None

# Cookie configuration details
COOKIE_NAME = "session"
CSRF_COOKIE = "csrf"

def get_current_user_id(session: Annotated[Optional[str], Cookie(alias=COOKIE_NAME)] = None) -> int:
    """
    Extract user ID from session cookie with improved error handling
    """
    if not session:
        raise HTTPException(401, detail="Not authenticated")
    
    try:
        if "_" not in session:
            raise ValueError("Invalid session format")
            
        sessionid, signature = session.rsplit("_", 1)
        expected_signature = auth.sign(sessionid)
        if not hmac.compare_digest(signature, expected_signature):
            raise HTTPException(401, detail="Invalid session")
        
        user_id = auth.db_get_session_user(sessionid)
        return user_id
    except ValueError:
        raise HTTPException(401, detail="Invalid session format")
    except RuntimeError as e:
        raise HTTPException(401, detail=str(e))
    except Exception as e:
        print(f"Authentication error: {e}")
        raise HTTPException(401, detail="Authentication failed")

# Display HTML pages
@app.get("/", response_class=HTMLResponse)
def display_login_page():
    possible_paths = ["static/login.html", "login.html"]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login</h1>
        <p>Login page file not found. Please ensure login.html is in the static/ directory.</p>
        <a href="/search">Go to Search (if already logged in)</a>
    </body>
    </html>
    """, status_code=200)

@app.get("/search", response_class=HTMLResponse)
def display_search_page():
    possible_paths = ["static/search.html", "search.html"]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    
    return HTMLResponse("<h1>Search page not found</h1>", status_code=404)

@app.get("/viewer", response_class=HTMLResponse)
def display_viewer_page():
    possible_paths = ["static/viewer.html", "viewer.html", "static/viewer_beta.html"]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    
    return HTMLResponse("<h1>Viewer page not found</h1>", status_code=404)

@app.get("/editor", response_class=HTMLResponse)
def display_editor_page():
    possible_paths = ["static/editor.html", "editor.html", "static/editor_beta.html"]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Simple Editor</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            input, textarea { width: 100%; margin: 10px 0; padding: 10px; }
            button { background: #4CAF50; color: white; padding: 10px 20px; border: none; cursor: pointer; }
            .back-btn { background: #666; margin-right: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Create Particle</h1>
            <form id="particle-form">
                <input type="text" id="title" placeholder="Title" required>
                <textarea id="body" placeholder="Content" rows="10" required></textarea>
                <button type="button" class="back-btn" onclick="window.location.href='/search'">Back</button>
                <button type="submit">Save Particle</button>
            </form>
        </div>
        
        <script>
            document.getElementById('particle-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                const title = document.getElementById('title').value;
                const body = document.getElementById('body').value;
                
                try {
                    const response = await fetch('/particles', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ title, body }),
                        credentials: 'include'
                    });
                    
                    if (response.ok) {
                        alert('Particle created successfully!');
                        window.location.href = '/search';
                    } else {
                        alert('Error creating particle');
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            });
        </script>
    </body>
    </html>
    """)

@app.get("/signup", response_class=HTMLResponse)
def display_signup_page():
    possible_paths = ["static/signup.html", "signup.html"]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("<h1>Signup page not found</h1>", status_code=404)

# Authentication endpoints
@app.post("/auth/login")
async def login_endpoint(creds: Credentials, request: Request):
    """Login endpoint that returns session cookie"""
    try:
        user_agent = request.headers.get("user-agent")
        client_ip = request.client.host if request.client else None
        
        session_token = auth.login(creds.username, creds.password, 
                                 user_agent=user_agent, ip=client_ip)
        
        if not session_token:
            raise HTTPException(401, detail="Invalid credentials")
        
        response = JSONResponse(content={"status": "success"})
        response.set_cookie(
            key=COOKIE_NAME,
            value=session_token,
            max_age=86400 * 7,
            httponly=True,
            secure=False,  
            samesite="lax",
            path="/"
        )
        
        return response
    
    except RuntimeError as e:
        raise HTTPException(429, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail="Login failed")

@app.post("/auth/signup")
async def signup_endpoint(creds: Credentials):
    """Create new user account"""
    try:
        user = auth.create_new_user(creds.username, creds.password)
        return {"status": "success", "user_id": user.user_id}
    except Exception as e:
        raise HTTPException(400, detail="Username already exists or signup failed")

@app.post("/auth/logout")
def logout_endpoint(session: Annotated[Optional[str], Cookie(alias=COOKIE_NAME)] = None):
    """Logout and clear session"""
    if session:
        try:
            sessionid = session.split("_", 1)[0] if "_" in session else session
            auth.logout(sessionid)
        except:
            pass 
    
    response = JSONResponse({"status": "success"})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response

# Particle endpoints 
@app.post("/particles")
def create_particle_endpoint(
    particle_data: ParticleCreate,
    user_id: int = Depends(get_current_user_id)
):
    """Create a new particle"""
    try:
        particle = particles.create_particle(
            user_id=str(user_id),
            title=particle_data.title,
            body=particle_data.body,
            db_path=DATABASE_FILE
        )
        return particle.to_dict()
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to create particle: {str(e)}")

@app.get("/particles")
def list_or_search_particles(
    query: Optional[str] = None,
    page: int = 1,
    page_size: int = 10,
    sort_by: str = "date_updated",
    fuzzy: Optional[int] = 0,
    user_id: int = Depends(get_current_user_id) 
):
    """
    List or search particles for the authenticated user.

    - If no query is provided → returns a paginated list.
    - If query is provided and fuzzy=0 → performs normal full-text search.
    - If query is provided and fuzzy=1 → performs fuzzy (edit-distance) search.

    :param query: Optional search query string.
    :param page: Page number (1-based).
    :param page_size: Number of results per page.
    :param sort_by: Field to sort results by (default: date_updated).
    :param fuzzy: 0 for exact, 1 for fuzzy search.
    :param user_id: User ID from dependency injection
    :returns: JSON serializable dict with paginated results.
    :raises HTTPException: If user is not authenticated.
    """
    try:
        if query:
            if fuzzy:
                return particles.fuzzy_search_particles(
                    user_id=str(user_id), 
                    query=query, 
                    page=page, 
                    page_size=page_size,
                    db_path=DATABASE_FILE
                )
            else:
                return particles.search_particles(
                    user_id=str(user_id), 
                    query=query, 
                    page=page, 
                    page_size=page_size, 
                    sort_by=sort_by,
                    db_path=DATABASE_FILE
                )
        else:
            return particles.list_particles(
                user_id=str(user_id), 
                page=page, 
                page_size=page_size, 
                sort_by=sort_by,
                db_path=DATABASE_FILE
            )
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to retrieve particles: {str(e)}")

@app.put("/particles/{particle_id}")
def update_particle_endpoint(
    particle_id: str,
    particle_data: ParticleUpdate,
    user_id: int = Depends(get_current_user_id)
):
    """
    Update a particle
    """
    try:
        particle = particles.update_particle(
            particle_id=particle_id,
            user_id=str(user_id),
            title=particle_data.title,
            body=particle_data.body,
            db_path=DATABASE_FILE
        )
        if not particle:
            raise HTTPException(404, detail="Particle not found")
        return particle.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to update particle: {str(e)}")

@app.delete("/particles/{particle_id}")
def delete_particle_endpoint(
    particle_id: str,
    user_id: int = Depends(get_current_user_id)
):
    """Delete a particle"""
    try:
        success = particles.delete_particle(particle_id, str(user_id), DATABASE_FILE)
        if not success:
            raise HTTPException(404, detail="Particle not found")
        return {"status": "deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to delete particle: {str(e)}")

@app.get("/particles/tags/all")
def get_all_tags_endpoint(user_id: int = Depends(get_current_user_id)):
    """Get all tags for the current user"""
    try:
        tags = particles.get_all_tags(str(user_id), DATABASE_FILE)
        return {"tags": tags}
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to get tags: {str(e)}")

@app.get("/particles/by-tag/{tag}")
def get_particles_by_tag_endpoint(
    tag: str,
    page: int = 1,
    page_size: int = 10,
    user_id: int = Depends(get_current_user_id)
):
    """Get particles by tag"""
    try:
        result = particles.get_particles_by_tag(
            user_id=str(user_id),
            tag=tag,
            page=page,
            page_size=page_size,
            db_path=DATABASE_FILE
        )
        return result
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to get particles by tag: {str(e)}")

@app.get("/particles/{particle_id}/references")
def get_particle_references_endpoint(
    particle_id: str,
    user_id: int = Depends(get_current_user_id)
):
    """Get particles that reference the given particle"""
    try:
        references = particles.get_particle_references(
            particle_id=particle_id,
            user_id=str(user_id),
            db_path=DATABASE_FILE
        )
        return {"references": [ref.to_dict() for ref in references]}
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to get particle references: {str(e)}")

@app.get("/particles/count")
def count_particles_endpoint(
    query: str = "",
    user_id: int = Depends(get_current_user_id)
):
    """Get particle count for user"""
    try:
        count = particles.count_particles(
            user_id=str(user_id),
            query=query,
            db_path=DATABASE_FILE
        )
        return {"count": count}
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to count particles: {str(e)}")

@app.get("/particles/{particle_id}")
def get_particle_endpoint(
    particle_id: str,
    user_id: int = Depends(get_current_user_id)
):
    """Get a specific particle by ID"""
    try:
        particle = particles.get_particle(
            particle_id=particle_id,
            user_id=str(user_id),
            db_path=DATABASE_FILE
        )
        if not particle:
            raise HTTPException(404, detail="Particle not found")
        return particle.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Failed to get particle: {str(e)}")