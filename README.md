Team Members

Member 1: KARISHMA SHAIK

Member 2: MADHURYA.M

Problem Statement Cybersecurity systems generate large numbers of threats such as malware, ransomware, and botnets. Managing these threats efficiently requires structured storage, fast search, and relationship analysis. This project builds a threat intelligence platform using graph-based data structures. *Data Structure Used Graph (Adjacency List) → to represent threat relationships

Hash Table → for fast threat lookup

Linked List → to store connected threats

Queue → for BFS traversal

Algorithm Explanation

1)Create threat nodes

2)Store node IDs in hash table

3)Connect threats using graph edges

4)Search threats by type

5)Traverse graph using BFS

6)Delete threats when needed

Compilation Instructions



Sample Output



Plain text Created threat 'APT29' Created threat 'Emotet' Added relationship: APT29 --> Emotet BFS Threat Propagation Analysis Demo Video Link (Add your video link here)
1. Abstract:

This project presents a cybersecurity threat intelligence platform implemented using data structures in C programming. The system stores threat information such as malware, ransomware, and advanced persistent threats in a graph model. Hash tables are used for fast searching, while breadth-first search helps analyze threat propagation. The platform performs CRUD operations efficiently and supports relationship analysis between threats.

2. Introduction:

Cybersecurity is important for protecting digital systems from attacks. Threat intelligence platforms help security analysts understand threat relationships and attack patterns. In this project, graph data structures are used to model cybersecurity threats and their dependencies.

3. Objectives:

Store cybersecurity threats efficiently

Perform CRUD operations on threats

Search threats quickly using hashing

Analyze threat propagation using BFS

Represent relationships among threats

4. Scope of the Project:

This project can be applied in: Security monitoring systems Malware analysis platforms Network defense systems Educational cybersecurity models

5. Literature Review:

Traditional cybersecurity systems mainly store threats in databases. Modern threat intelligence platforms use graph models because they better represent relationships between attacks. Graph-based threat analysis is widely used in industry tools like Cisco and IBM.

6. Methodology:

The project follows these steps: 1)Initialize graph and hash table

2)Create threat nodes

3)Add relationships

4)Search threats

5)Traverse graph using BFS

6)Delete threats

7. Technology Used:

Programming Language: C

Compiler: GCC

Data Structures: Graph, Hash Table, Queue, Linked List

Platform: Linux / Windows

8. Architecture / System Design:

System flow: Plain text User Input → Hash Table Lookup → Graph Storage → BFS Analysis → Output

Modules:

Threat Creation Module

Threat Search Module

Relationship Module

BFS Analysis Module

9. Implementation Details:

Your code includes:

create_threat() → creates new threat node

read_threat() → displays threat

update_relationship() → connects threats

delete_threat() → removes threat

bfs_threat_analysis() → analyzes propagation

10. Results / Output:

The program successfully performs:

✅ Threat creation

✅ Threat search

✅ Relationship creation

✅ BFS traversal

✅ Threat deletion

Sample threats used:

APT29

Emotet

WannaCry

Mirai

11. Conclusion:

This project demonstrates how data structures improve cybersecurity threat management. Graph representation helps understand threat relationships clearly, while hashing improves search speed.

12. Future Work:

Add DFS analysis

Add file storage

Add real-time threat feed

Integrate machine learning

13. Footnotes / References:

Data Structures Using C

Computer Security Principles and Practice

National Institute of Standards and Technology
