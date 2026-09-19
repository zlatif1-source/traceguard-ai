import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.embeddings import Embedder


@dataclass(frozen=True)
class SearchResult:
    document_id: str
    title: str
    url: str
    text: str
    score: float


class SQLiteVectorStore:
    """A transparent vector store built on SQLite for a portfolio-sized dataset."""

    def __init__(self, database_path: Path, embedder: Embedder) -> None:
        self.database_path = database_path
        self.embedder = embedder
        self._create_table()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _create_table(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_chunks (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    text TEXT NOT NULL,
                    embedding TEXT NOT NULL,
                    embedder TEXT NOT NULL
                )
                """
            )

    def replace_documents(self, documents: list[dict[str, str]]) -> None:
        embeddings = self.embedder.embed([document["text"] for document in documents])
        rows = [
            (
                document["id"],
                document["title"],
                document["url"],
                document["text"],
                json.dumps(embedding),
                self.embedder.name,
            )
            for document, embedding in zip(documents, embeddings, strict=True)
        ]

        with self._connect() as connection:
            connection.execute("DELETE FROM knowledge_chunks")
            connection.executemany(
                """
                INSERT INTO knowledge_chunks (id, title, url, text, embedding, embedder)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def search(self, query: str, top_k: int = 3) -> list[SearchResult]:
        query_vector = np.array(self.embedder.embed([query])[0], dtype=float)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, title, url, text, embedding
                FROM knowledge_chunks
                WHERE embedder = ?
                """,
                (self.embedder.name,),
            ).fetchall()

        results: list[SearchResult] = []
        for row in rows:
            document_vector = np.array(json.loads(row["embedding"]), dtype=float)
            score = float(np.dot(query_vector, document_vector))
            results.append(
                SearchResult(
                    document_id=row["id"],
                    title=row["title"],
                    url=row["url"],
                    text=row["text"],
                    score=score,
                )
            )

        return sorted(results, key=lambda result: result.score, reverse=True)[:top_k]

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM knowledge_chunks").fetchone()
        return int(row["total"])
