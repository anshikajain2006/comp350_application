import sqlite3
from dataclasses import asdict
from typing import List

def convert_to_csstring(lst: list) -> str:
    """
    Convert a list of strings into a single comma-separated string.

    :param lst: List of string values to convert
    :type lst: list
    :return: Comma-separated string representation of the list
    :rtype: str
    """
    return ",".join(lst) if lst else ""


def cstring_to_list(cstring: str) -> list:
    """
    Convert a comma-separated string into a list of strings.

    :param cstring: Comma-separated string to convert
    :type cstring: str
    :return: List of strings obtained from the input string
    :rtype: list
    """
    return cstring.split(",") if cstring else []


def store_user(user: User) -> None:
    """
    Store a User object into the Users table in the database.

    :param user: User object containing username, password, and token
    :type user: User
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    user_dict = asdict(user)
    # Remove user_id as it is AUTOINCREMENT
    del user_dict["user_id"]
    return cur.execute(
        'INSERT INTO Users (username, password, token) VALUES (:username, :password, :token)', 
        user_dict
    ) and con.commit()


def store_particle(particle: Particle) -> None:
    """
    Store a Particle object into the Particles table in the database.

    :param particle: Particle object containing metadata (title, body, tags, references, etc.)
    :type particle: Particle
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    particle_dict = asdict(particle)
    del particle_dict["particle_id"]
    particle_dict["tags"] = convert_to_csstring(particle_dict["tags"])
    particle_dict["particle_references"] = convert_to_csstring(particle_dict["particle_references"])
    return cur.execute(
        'INSERT INTO Particles (date_created, date_updated, title, body, tags, particle_references) '
        'VALUES (:date_created, :date_updated, :title, :body, :tags, :particle_references)', 
        particle_dict
    ) and con.commit()

#test block 3
store_user(alvin)
store_particle(alvin_particle)