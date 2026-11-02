# pgutil: Plan

1. **Module and helpers.** Rename the module, move the go-pg helpers to a
   deprecated package, and add identifiers, URLs and SQLSTATE codes.
2. **SCRAM verifiers.**
3. **Provisioning and verification**, tested against a real server.
4. **Release v0.2.0.** The module's earlier tags carry its previous path, so
   its first release under this path is v0.2.0.
5. **App-role helpers** for applications' migrations: ensure the database
   and the app role, refuse a privileged role, and grant the app role rows
   in the owner's tables, replacing copies kept in applications.
