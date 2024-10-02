```
sequenceDiagram 
    participant client as Client
    opt Token Request Sequence
        create participant ste as Session Token Endpoint
        client->>ste: Public Key
        participant appserv as Application Server 
        participant encserv as Encryption Service 
        ste->>encserv: Encrypt session token
        encserv->>ste: 
        destroy ste
        ste->>client: Encrypted SessionToken
        
    end
    loop Application Request Sequence
        client->>appserv: Signed request with token
        appserv->>encserv: Decrypt token
        encserv->>appserv: 
        appserv->>appserv: Verify the request with the decrypted key
        appserv->>client: Response to signed request
    end
```