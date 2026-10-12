import networkx as nx
from typing import List
from contracts.models import Session, Graph, GraphNode, GraphEdge, Campaign
from contracts.normalize import node_id

def build_graph(sessions: list[Session]) -> Graph:
    G = nx.Graph()
    nodes = {}
    edges = []
    
    bare_shorteners = {"bit.ly", "t.me", "wa.me", "tinyurl.com"}
    
    for s in sessions:
        s_node_id = s.id
        nodes[s_node_id] = GraphNode(id=s_node_id, type="session", label=f"{s.scam_type} · {s.id[2:6]}")
        G.add_node(s_node_id, type="session", orig_id=s.id, created_at=s.created_at)
        
        for e in s.entities:
            e_node_id = node_id(e.type, e.value)
            
            # Skip merging for bare shorteners, but still draw node
            is_bare = e.type == "url" and e.value in bare_shorteners
            
            if e_node_id not in nodes:
                nodes[e_node_id] = GraphNode(id=e_node_id, type=e.type, label=e.value)
            
            edges.append(GraphEdge(source=s_node_id, target=e_node_id, type="mentions"))
            if not is_bare:
                G.add_edge(s_node_id, e_node_id)
                
    campaigns = []
    c_idx = 1
    components = list(nx.connected_components(G))
    
    # Filter and sort components
    valid_comps = []
    for comp in components:
        sess_nodes = [n for n in comp if G.nodes[n].get("type") == "session"]
        if len(sess_nodes) >= 2:
            earliest = min(G.nodes[n]["created_at"] for n in sess_nodes)
            valid_comps.append((len(sess_nodes), earliest, comp, sess_nodes))
            
    valid_comps.sort(key=lambda x: (x[0], x[1] == "0", x[1]), reverse=True) # size desc, earliest asc
    
    for _, _, comp, sess_nodes in valid_comps:
        c_id = f"c_{c_idx}"
        c_idx += 1
        
        shared_ent = []
        ent_counts = {}
        scam_types = []
        
        for s_id in sess_nodes:
            nodes[s_id].campaign_id = c_id
            s_obj = next(s for s in sessions if s.id == s_id)
            scam_types.append(s_obj.scam_type)
            
            for e in s_obj.entities:
                e_id = node_id(e.type, e.value)
                if not (e.type == "url" and e.value in bare_shorteners):
                    ent_counts[e_id] = ent_counts.get(e_id, 0) + 1
                    
        for e_id, count in ent_counts.items():
            if count >= 2:
                shared_ent.append(e_id)
                nodes[e_id].campaign_id = c_id
                
        dominant_scam = max(set(scam_types), key=scam_types.count) if scam_types else "other"
        
        campaigns.append(Campaign(
            id=c_id,
            session_ids=sorted(sess_nodes),
            shared_entities=sorted(shared_ent),
            size=len(sess_nodes),
            dominant_scam_type=dominant_scam
        ))

    return Graph(
        nodes=list(nodes.values()),
        edges=edges,
        campaigns=campaigns
    )