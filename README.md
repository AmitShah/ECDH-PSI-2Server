# ECDH-PSI-2Server
This is an implementation of a multiparty PSI using Multiparty ECDH with non-colluding servers. Atleast 1 server must remain honest for this scheme to work (thinking covid19 state run servers)

This was developed as a proof of concept for Covid19 tracking.

Initially I designed a Partically Homomorphic Encryption scheme using EC ElGamal and Oblivious Polynomial Evaluation but this proved to be non-performant.

This multipary DH based approach is much faster:

There are 2 phases to the protocol: Upload and Offline Phase (Alice) and Querying Phase (Bob).

All the servers are treated equally, and the protocol maintains privacy as long as at least 1 server remains honest.  The beauty of the protocol is its simplicity to understand.

Lets consider a sceneario with 2 servers: S1,S2
S1,S2 generate asymmetric keyPairs (G^r1, G^r2) and perform a DHKE to define a ServerKey = G^r1r2
S1,S2 publish they public keys and shared ServerKey
H() is a cryptographic hash function
We use an elliptic curve field from herein 

1)Phase 1 Upload and Offline

Alice Generates a keyPair: G^x
Alice encodes her message m_alice: [C1=G^x, C2=G^x*H(m_alice)*r1)] uploaded to S1/S2 
Alice can go offline

2) Query Phase

Bob creates an ephemereal secret y
Bob queries S2
S2 responds with [C1^r2=G^x*r2, C2 ] -> Bob
Bob calculates [G^x*r2*H(m_bob)+y] and send this to S1
S1 calculates [(G^x*r2*H(m_bob)+y)*r1] and sends this back to Bob
Bob calculate [ [G^x*r2*h(m_bob)+y]*r1 - [C2]]= G^r1*y = S1_PublicKey*y iff H(m_bob)==H(m_alice)
Bob can easily calculate S1_PublicKey*y 


This scheme can be expanded to any number of servers and will preserve privacy as long as one of the servers remains honest. 
We can cycle private keys on the servers to "delete" data; Any single server cycling a key will render the data worthless

Further Ideas:
-Rate limiting should be enforced on the servers to limit sybil attacks
-Servers are setup in swarm, allows anyone to run a server (considering limits to DHKE)
-A bond should be setup on the Server private keys that may be claimed if a server leaks its private key (decinventivize collusion and key sharing)
