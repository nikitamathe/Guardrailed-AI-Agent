import os
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import CharacterTextSplitter

class SecurityLogRAG:
    def __init__(self, log_file_path: str = "security.log"):
        self.log_file_path = log_file_path
        self.vector_store = None
        self._initialize_rag()

    def _initialize_rag(self):
        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(f"Log file not found at {self.log_file_path}")

        # Load security log lines
        loader = TextLoader(self.log_file_path)
        documents = loader.load()

        # Split into individual chunked log entries
        text_splitter = CharacterTextSplitter(chunk_size=150, chunk_overlap=0, separator="\n")
        docs = text_splitter.split_documents(documents)

        # Initialize local HuggingFace embeddings
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

        # Create FAISS vector store
        self.vector_store = FAISS.from_documents(docs, embeddings)

    def query_logs(self, query: str, k: int = 2) -> list[str]:
        """Perform similarity search on vector database."""
        results = self.vector_store.similarity_search(query, k=k)
        return [doc.page_content for doc in results]

if __name__ == "__main__":
    print("=== Testing Security Log RAG Engine ===")
    rag = SecurityLogRAG()
    
    # Query 1: Retrieve brute force incidents
    results = rag.query_logs("brute force attack IP")
    print("\n[Query Result - Brute Force]:")
    for res in results:
        print(f" - {res}")

    # Query 2: Retrieve SQL injection logs
    results_sql = rag.query_logs("SQL injection")
    print("\n[Query Result - SQL Injection]:")
    for res in results_sql:
        print(f" - {res}")