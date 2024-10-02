```
sequenceDiagram
    participant client as Client
    participant proxy as Proxy Server
    participant github as GitHub
    proxy->>github: Get users' keys
    client->>proxy: Signed request
    proxy->>proxy: Look up the GitHub user for the given KeyID, validate the request signature
    participant k8s as Kubernetes
    proxy->>k8s: Add X-Remote-User and X-Remote-Group headers
    k8s->>proxy: 
    proxy->>client: 
```