```
sequenceDiagram
    participant client as Client
    participant appserv as Application Server
    participant github as GitHub
    appserv->>github: Get users' keys
    client->>appserv: Signed request
    appserv->>appserv: Look up the GitHub user for the given KeyID, validate the request signature
    appserv->>client: Respond to the user's request
```