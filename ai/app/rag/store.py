"""[3] VECTOR STORE + [5] RETRIEVAL : ChromaDB (vecteurs uniquement)."""
import chromadb

client = chromadb.PersistentClient(path="chroma_data")
collection = client.get_or_create_collection(
    name="soc_alerts",
    metadata={"hnsw:space": "cosine"})


def add(ids, embeddings, documents, metadatas):
    """[3] stocke les vecteurs."""
    collection.upsert(ids=ids, embeddings=embeddings,
                      documents=documents, metadatas=metadatas)


def search(embedding, k=3):
    """[5] similarite cosinus -> top k."""
    return collection.query(query_embeddings=[embedding], n_results=k)