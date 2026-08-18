import os
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import CharacterTextSplitter

class RAGLogEngine:
    def __init__(self, log_file_path: str = "security.log"):
        self.log_file_path = log_file_path
        self.vector_store = None
        self._initialize_rag()

    def _initialize_rag(self):
        # Create security.log with mock data if it doesn't exist
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("[2026-08-17 20:10:02] WARNING sshd: Failed password for root from 192.168.1.105 port 22\n")
                f.write("[2026-08-17 20:10:05] WARNING sshd: Failed password for root from 192.168.1.105 port 22\n")
                f.write("[2026-08-17 20:11:12] CRITICAL nginx: Possible SQL Injection: 'UNION SELECT username, password FROM users'\n")
                f.write("[2026-08-17 20:12:00] INFO systemd: Service nginx restarted via agent rule\n")
                f.write("[2026-08-17 20:15:30] CRITICAL firewall: Port scan detected from IP 10.0.4.88 across ports 21, 22, 80, 443\n")

        loader = TextLoader(self.log_file_path)
        documents = loader.load()

        text_splitter = CharacterTextSplitter(chunk_size=150, chunk_overlap=0, separator="\n")
        docs = text_splitter.split_documents(documents)

        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        self.vector_store = FAISS.from_documents(docs, embeddings)

    def query(self, query: str, k: int = 2) -> list[str]:
        """Perform similarity search on FAISS vector database."""
        if not self.vector_store:
            return []
        results = self.vector_store.similarity_search(query, k=k)
        return [doc.page_content for doc in results]

    def query_logs(self, query: str, k: int = 2) -> list[str]:
        return self.query(query, k=k)