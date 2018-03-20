# Basic Authentication for REST API

This adapter/extension allows clients to access the API without OAuth.

### Caution

I use this for local testing only.
If you wish to install on a site which can be accessed widely then you should _really_ use HTTPS always.
This is because HTTP basic authentication is unencrypted.
It would be trivial for an eavesdropper to extract usernames and passwords.

Furthermore, this extension does not start a `WWW-Authenticate` challenge as that would break guest access.
Viewing a resource in a browser will not prompt for username and password automatically.
Your client must supply credentials directly and with every request,
so it is important to use HTTPS or find some other way to shield traffic.

### How it works

- If a request has no `Authorization` header then the user is a guest and can only access guest resources.
- If a request has an `Authorization` header starting with "OAuth" then normal OAuth behaviour applies.
- If a request has an `Authorization` header starting with "Basic" then:
  - If the username/password matches an active admin account then the user is an admin and may access admin resources.
  - If the username/password matches an active customer account then the user is a customer and may access customer resources.
  - If neither matches then a "401 Unauthorized" error occurs.
