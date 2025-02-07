import os
import json
import networkx as nx
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# Initialize embedding model and FAISS index
model = SentenceTransformer("all-MiniLM-L6-v2")
index = faiss.IndexFlatL2(384)  # 384 dimensions for MiniLM embeddings

def load_json_files(path):
    """Load relevant JSON files from a directory or a single file."""
    json_files = []
    if os.path.isdir(path):
        for file in os.listdir(path):
            if file.endswith(".json"):
                json_files.append(os.path.join(path, file))
    elif path.endswith(".json"):
        json_files.append(path)
    
    data = []
    for file in json_files:
        with open(file, "r", encoding="utf-8") as f:
            try:
                content = json.load(f)
                data.append(content)
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON file: {file}")
    return data

def build_knowledge_graph(data):
    """Build a NetworkX knowledge graph from MITRE ATT&CK JSON data."""
    G = nx.DiGraph()
    
    for entry in data:
        if "objects" in entry:
            for obj in entry["objects"]:
                if obj.get("type") in ["attack-pattern", "malware", "tool", "relationship"]:
                    node_id = obj.get("id", obj.get("external_id", "unknown"))
                    node_name = obj.get("name", obj.get("id", "Unnamed"))
                    
                    G.add_node(node_id, label=node_name, type=obj["type"])
                    
                    if obj.get("type") == "relationship":
                        source_ref = obj.get("source_ref")
                        target_ref = obj.get("target_ref")
                        rel_type = obj.get("relationship_type", "related-to")
                        if source_ref and target_ref:
                            G.add_edge(source_ref, target_ref, relationship=rel_type)
    
    return G

def generate_embeddings_and_index(G):
    """Generate embeddings for nodes and store them in a FAISS index."""
    node_list = list(G.nodes(data=True))
    texts = [node[1].get('label', 'Unknown') for node in node_list]
    embeddings = model.encode(texts, convert_to_numpy=True)
    
    # Normalize embeddings before adding to FAISS
    faiss.normalize_L2(embeddings)
    index.add(embeddings)
    
    # Store embeddings in node attributes
    for i, (node_id, attr) in enumerate(node_list):
        G.nodes[node_id]['embedding'] = embeddings[i]
    
    return index

if __name__ == "__main__":
    path = "path/to/json/files"  # Change this to your actual file or directory
    json_data = load_json_files(path)
    knowledge_graph = build_knowledge_graph(json_data)
    faiss_index = generate_embeddings_and_index(knowledge_graph)
    
    # Placeholder for future visualization
    # nx.draw(knowledge_graph, with_labels=True)
    print("Knowledge graph and FAISS index successfully created!")