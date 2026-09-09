"""TriNetra FastAPI backend package.

Run the API with:

    uvicorn backend.app.main:app --reload

NOTE: this package deliberately does *not* re-export the FastAPI ``app``,
because doing so (``from backend.app.main import app``) shadows the
``backend.app`` submodule attribute and breaks ``import backend.app.main``.
"""