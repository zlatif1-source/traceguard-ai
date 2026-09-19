import json
from pathlib import Path

from app.vector_store import SQLiteVectorStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_PATH = PROJECT_ROOT / "data" / "knowledge_base.json"


def load_knowledge() -> list[dict[str, str]]:
    return json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))


def ensure_knowledge_index(store: SQLiteVectorStore) -> None:
    documents = load_knowledge()
    if store.count() != len(documents):
        store.replace_documents(documents)
