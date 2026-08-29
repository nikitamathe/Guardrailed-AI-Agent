import ipaddress
import os
import re
from pathlib import Path
from typing import List, Optional

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


class RAGLogEngine:
    """FAISS retrieval engine over a SIEM security log.

    Behavior notes:
      - Refuses to fabricate log data: a missing or empty log file raises a
        clear error instead of seeding fake events.
      - Persists the built FAISS index and only rebuilds when the source log
        changes (mtime-based), avoiding cold-start rebuilds.
      - Chunks log lines with overlap and per-line metadata, and filters
        retrieval results below a configurable similarity threshold so
        irrelevant records never reach the prompt.
      - Exposes PII-redacted context via ``get_sanitized_context()`` so IPs,
        usernames and emails are masked before LLM context injection.
    """

    _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{0,4}\b")
    _EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
    _USERNAME_RE = re.compile(r"\b(?:user|username|login|auth)\s*[:=]\s*\"?([\w.-]+)\b", re.IGNORECASE)
    _PASSWORD_FOR_USER_RE = re.compile(r"\bpassword\s+for\s+([\w.-]+)\b", re.IGNORECASE)
    _SSH_FOR_USER_RE = re.compile(r"\bfor\s+([\w.-]+)\s+from\b", re.IGNORECASE)
    _ADMIN_NAME_RE = re.compile(r"\badmin\s+([\w.-]+)\b", re.IGNORECASE)

    def __init__(
        self,
        log_file_path: str = "security.log",
        embedding_model: str = "all-MiniLM-L6-v2",
        chunk_size: int = 512,
        chunk_overlap: int = 64,
        persist_directory: Optional[str] = None,
        similarity_threshold: Optional[float] = 1.0,
        allow_dangerous_deserialization: bool = True,
    ):
        self.log_file_path = log_file_path
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.persist_directory = persist_directory or os.path.join(
            os.path.dirname(os.path.abspath(log_file_path)), ".faiss_index"
        )
        self.similarity_threshold = similarity_threshold
        self.allow_dangerous_deserialization = allow_dangerous_deserialization

        self.vector_store = None
        self._embeddings_model = None
        self._initialized = False

    def _ensure_initialized(self):
        if self._initialized:
            return

        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(
                f"Security log file not found: '{self.log_file_path}'. "
                "Refusing to fabricate sample events. Create the log file or "
                "point RAGLogEngine at an existing SIEM log."
            )

        mtime = os.path.getmtime(self.log_file_path)
        if self.allow_dangerous_deserialization and self._index_is_current(mtime):
            self._load_index()
        else:
            self._build_index(mtime)
        self._initialized = True

    def _embeddings(self) -> HuggingFaceEmbeddings:
        if self._embeddings_model is None:
            self._embeddings_model = HuggingFaceEmbeddings(model_name=self.embedding_model)
        return self._embeddings_model

    def _build_index(self, mtime: float):
        raw = Path(self.log_file_path).read_text(encoding="utf-8", errors="replace")
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            raise ValueError(f"Log file '{self.log_file_path}' is empty; nothing to index.")

        # PII sanitization at ingestion: mask IPs / usernames / emails before the
        # document is embedded, indexed and persisted to disk, so raw PII never
        # lands in the FAISS artifacts (.pkl / .faiss) or the index metadata.
        sanitized_lines = [self.sanitize(line) for line in lines]

        source = str(Path(self.log_file_path).resolve())
        docs = [
            Document(page_content=content, metadata={"source": source, "line": idx})
            for idx, content in enumerate(sanitized_lines, start=1)
        ]

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            separators=["\n\n", "\n", " "],
        )
        chunks = splitter.split_documents(docs)

        os.makedirs(self.persist_directory, exist_ok=True)
        self.vector_store = FAISS.from_documents(chunks, self._embeddings())
        self.vector_store.save_local(self.persist_directory)
        self._write_marker(mtime)

    def _load_index(self):
        self.vector_store = FAISS.load_local(
            self.persist_directory,
            self._embeddings(),
            allow_dangerous_deserialization=self.allow_dangerous_deserialization,
        )

    def _index_is_current(self, mtime: float) -> bool:
        marker = os.path.join(self.persist_directory, "index.metadata")
        if not os.path.isdir(self.persist_directory) or not os.path.exists(marker):
            return False
        if not os.path.isfile(os.path.join(self.persist_directory, "index.faiss")):
            return False
        if not os.path.isfile(os.path.join(self.persist_directory, "index.pkl")):
            return False
        try:
            with open(marker, encoding="utf-8") as fh:
                stored_path, stored_mtime = fh.read().splitlines()[:2]
        except (OSError, ValueError, IndexError):
            return False
        return stored_path == self.log_file_path and int(stored_mtime) == int(mtime)

    def _write_marker(self, mtime: float):
        with open(os.path.join(self.persist_directory, "index.metadata"), "w", encoding="utf-8") as fh:
            fh.write(f"{self.log_file_path}\n{int(mtime)}\n")

    def query(
        self,
        query: str,
        k: int = 2,
        similarity_threshold: Optional[float] = None,
    ) -> List[str]:
        """Similarity search with threshold filtering (lower score = more similar)."""
        self._ensure_initialized()
        if not self.vector_store:
            return []

        k = max(1, int(k))
        threshold = self.similarity_threshold if similarity_threshold is None else similarity_threshold

        results = []
        for doc, score in self.vector_store.similarity_search_with_score(query, k=k):
            if threshold is not None and score > threshold:
                continue
            results.append(doc.page_content)
        return results

    def sanitize(self, text: str) -> str:
        """Mask IPs, usernames and emails in a single log fragment."""
        if not text:
            return text
        text = self._EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        text = self._IPV4_RE.sub(self._mask_ipv4, text)
        text = self._IPV6_RE.sub("[REDACTED_IPV6]", text)
        text = self._USERNAME_RE.sub("user: [REDACTED_USER]", text)
        text = self._PASSWORD_FOR_USER_RE.sub("password for [REDACTED_USER]", text)
        text = self._SSH_FOR_USER_RE.sub("for [REDACTED_USER] from", text)
        text = self._ADMIN_NAME_RE.sub("admin [REDACTED_USER]", text)
        return text

    def get_sanitized_context(self, query: str, k: int = 2) -> List[str]:
        """Retrieve top-k context with PII redacted, safe for LLM prompt injection."""
        return [self.sanitize(fragment) for fragment in self.query(query, k=k)]

    def _mask_ipv4(self, match: re.Match) -> str:
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.*.*"