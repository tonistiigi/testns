wip

Sandboxed environments for testing purposes

goals:

- Only dependancy is having docker installed. Cancelling a test or unexpected failure should not leak any open processes or mounts.

- Every namespace can run its own Docker daemon. Frozen images support built in.

- Every namespace has its own IP and local storage but shares mount namespace.

- Pool of namespaces for parallel usage.

- Shared storage allows to test different drivers and reuse already created storage without reloading frozen images and recreating a loopback.

- Shared daemons. Daemon can be reused without restarting, content will be reset to initial set of frozen images.


