#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Max nodes and edges
#define MAX_NODES 100
#define MAX_NAME_LEN 50
#define MAX_THREAT_TYPES 10

// Threat Node Structure
typedef struct ThreatNode {
    char name[MAX_NAME_LEN];
    char threat_type[MAX_NAME_LEN];
    int severity; // 1-10
    int id;
    struct ThreatNode* next;
} ThreatNode;

// Graph using Adjacency List
typedef struct {
    ThreatNode* nodes[MAX_NODES];
    int num_nodes;
    int node_ids[MAX_NODES];
} ThreatGraph;

// Hash table for fast node lookup
typedef struct HashEntry {
    char name[MAX_NAME_LEN];
    int id;
    struct HashEntry* next;
} HashEntry;

typedef struct {
    HashEntry* table[MAX_NODES];
} HashTable;

// Global graph and hash table
ThreatGraph graph;
HashTable hash_table;

// Hash function
unsigned int hash_function(char* str) {
    unsigned int hash = 0;
    while (*str) {
        hash = hash * 31 + (*str++);
    }
    return hash % MAX_NODES;
}

// Initialize hash table
void init_hash_table() {
    for (int i = 0; i < MAX_NODES; i++) {
        hash_table.table[i] = NULL;
    }
}

// Insert into hash table
void hash_insert(char* name, int id) {
    unsigned int index = hash_function(name);
    HashEntry* new_entry = (HashEntry*)malloc(sizeof(HashEntry));
    strcpy(new_entry->name, name);
    new_entry->id = id;
    new_entry->next = hash_table.table[index];
    hash_table.table[index] = new_entry;
}

// Search hash table
int hash_search(char* name) {
    unsigned int index = hash_function(name);
    HashEntry* current = hash_table.table[index];
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current->id;
        }
        current = current->next;
    }
    return -1;
}

// Initialize graph
void init_graph() {
    graph.num_nodes = 0;
    for (int i = 0; i < MAX_NODES; i++) {
        graph.nodes[i] = NULL;
        graph.node_ids[i] = -1;
    }
    init_hash_table();
}

// CREATE: Add new threat node
bool create_threat(char* name, char* threat_type, int severity) {
    if (graph.num_nodes >= MAX_NODES || hash_search(name) != -1) {
        printf("❌ Node creation failed: Max nodes reached or name exists\n");
        return false;
    }
    
    ThreatNode* new_node = (ThreatNode*)malloc(sizeof(ThreatNode));
    strcpy(new_node->name, name);
    strcpy(new_node->threat_type, threat_type);
    new_node->severity = severity;
    new_node->id = graph.num_nodes;
    new_node->next = NULL;
    
    graph.nodes[graph.num_nodes] = new_node;
    graph.node_ids[graph.num_nodes] = graph.num_nodes;
    hash_insert(name, graph.num_nodes);
    
    printf("✅ Created threat '%s' (ID: %d, Type: %s, Severity: %d)\n", 
           name, graph.num_nodes, threat_type, severity);
    graph.num_nodes++;
    return true;
}

// READ: Display single node
void read_threat(int id) {
    if (id < 0 || id >= graph.num_nodes || graph.nodes[id] == NULL) {
        printf("❌ Node ID %d not found\n", id);
        return;
    }
    
    ThreatNode* node = graph.nodes[id];
    printf("🔍 Threat ID: %d\n", id);
    printf("   Name: %s\n", node->name);
    printf("   Type: %s\n", node->threat_type);
    printf("   Severity: %d/10\n", node->severity);
}

// READ: Display all threats
void read_all_threats() {
    printf("\n📊 Threat Intelligence Graph (%d nodes):\n", graph.num_nodes);
    printf("=====================================\n");
    for (int i = 0; i < graph.num_nodes; i++) {
        if (graph.nodes[i]) {
            read_threat(i);
            printf("---\n");
        }
    }
}

// UPDATE: Add relationship (edge) between threats
bool update_relationship(char* from_name, char* to_name, char* relation_type) {
    int from_id = hash_search(from_name);
    int to_id = hash_search(to_name);
    
    if (from_id == -1 || to_id == -1) {
        printf("❌ Relationship failed: Source or target threat not found\n");
        return false;
    }
    
    // Add edge from from_id to to_id (undirected for simplicity)
    ThreatNode* from_node = graph.nodes[from_id];
    ThreatNode* new_edge = (ThreatNode*)malloc(sizeof(ThreatNode));
    strcpy(new_edge->name, to_name);
    strcpy(new_edge->threat_type, relation_type);
    new_edge->severity = 0;
    new_edge->id = to_id;
    new_edge->next = from_node->next;
    from_node->next = new_edge;
    
    printf("🔗 Added relationship: %s --[%s]--> %s\n", from_name, relation_type, to_name);
    return true;
}

// DELETE: Remove threat node and its relationships
bool delete_threat(char* name) {
    int id = hash_search(name);
    if (id == -1) {
        printf("❌ Threat '%s' not found\n", name);
        return false;
    }
    
    // Free node and its relationships
    ThreatNode* current = graph.nodes[id];
    while (current) {
        ThreatNode* temp = current;
        current = current->next;
        free(temp);
    }
    graph.nodes[id] = NULL;
    graph.node_ids[id] = -1;
    
    // Remove from hash table (simplified - mark as deleted)
    printf("🗑️ Deleted threat '%s' (ID: %d)\n", name, id);
    return true;
}

// Graph traversal - BFS for threat propagation analysis
void bfs_threat_analysis(int start_id) {
    if (start_id < 0 || start_id >= graph.num_nodes || graph.nodes[start_id] == NULL) {
        printf("❌ Invalid start node for BFS\n");
        return;
    }
    
    bool visited[MAX_NODES] = {false};
    int queue[MAX_NODES], front = 0, rear = 0;
    
    queue[rear++] = start_id;
    visited[start_id] = true;
    
    printf("\n🔍 BFS Threat Propagation Analysis from %s:\n", 
           graph.nodes[start_id]->name);
    
    while (front < rear) {
        int current = queue[front++];
        ThreatNode* node = graph.nodes[current];
        
        printf("  → %s (relationships: ", node->name);
        ThreatNode* neighbor = node->next;
        bool first = true;
        while (neighbor) {
            if (!visited[neighbor->id]) {
                queue[rear++] = neighbor->id;
                visited[neighbor->id] = true;
            }
            if (!first) printf(", ");
            printf("%s", neighbor->name);
            first = false;
            neighbor = neighbor->next;
        }
        printf(")\n");
    }
}

// Search by threat type
void search_by_type(char* threat_type) {
    printf("\n🔎 Threats of type '%s':\n", threat_type);
    bool found = false;
    for (int i = 0; i < graph.num_nodes; i++) {
        if (graph.nodes[i] && strcmp(graph.nodes[i]->threat_type, threat_type) == 0) {
            read_threat(i);
            found = true;
        }
    }
    if (!found) printf("No threats found\n");
}

int main() {
    printf("🔐 Cybersecurity Threat Intelligence Graph CRUD\n");
    printf("===============================================\n");
    init_graph();
    
    // Sample data - CREATE
    create_threat("APT29", "Advanced Persistent Threat", 9);
    create_threat("Emotet", "Malware", 8);
    create_threat("WannaCry", "Ransomware", 10);
    create_threat("Mirai", "IoT Botnet", 7);
    
    // READ all
    read_all_threats();
    
    // UPDATE - Add relationships
    update_relationship("APT29", "Emotet", "delivers");
    update_relationship("Emotet", "WannaCry", "drops");
    update_relationship("APT29", "Mirai", "C2");
    
    // READ specific
    printf("\n📋 Detailed view:\n");
    read_threat(0); // APT29
    
    // BFS Analysis
    bfs_threat_analysis(0);
    
    // Search by type
    search_by_type("Malware");
    
    // DELETE
    delete_threat("Mirai");
    read_all_threats();
    
    printf("\n✅ Threat Intelligence Graph operations completed!\n");
    printf("Data Structures Used:\n");
    printf("- Graph (Adjacency List)\n");
    printf("- Hash Table (O(1) lookups)\n");
    printf("- Linked Lists (relationships)\n");
    printf("- BFS Queue (propagation analysis)\n");
    
    return 0;
}