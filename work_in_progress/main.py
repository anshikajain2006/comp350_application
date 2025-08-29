from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os
from pydantic import BaseModel, Field
from uuid import UUID
from dataclasses import dataclass
from datetime import datetime

import latest_walking_skeleton as pim

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def display_pim_loginpage():
    with open("static/PIM_loginpage.html") as plp:
        html_content = plp.read()
    return HTMLResponse(content=html_content)

@app.get("/search", response_class=HTMLResponse)
async def display_pim_searchpage():
    with open("static/PIM_searchpage.html") as psp:
        html_content = psp.read()
    return HTMLResponse(content=html_content)

@app.get("/extended_particle_viewer", response_class=HTMLResponse)
async def display_pim_extended_particle_viewer():
    with open("static/PIM_extended_particle_viewer.html") as pepv:
        html_content = pepv.read()
    return HTMLResponse(content=html_content)

@app.get("/particle_editor", response_class=HTMLResponse)
async def display_pim_particle_editor():
    with open("static/PIM_particle_editor.html") as ppe:
        html_content = ppe.read()
    return HTMLResponse(content=html_content)

@dataclass
class User:
  id: int | None # will be added via sql
  username: str
  password: str
  token: str | None

@dataclass
class Particle:
  id: int | None # will be added via sql
  date_created: datetime
  date_updated: datetime
  title: str
  body: str
  tags: list[str]
  particle_references: list[str]


# Once the module is fixed, create handlers like the one below to call the relevant function, don't copy over the functions form the skeleton

@app.post("/")
def handler(username: str, password: str): #type-casting it to User seems to break it
    return pim.create_new_user(username, password)
