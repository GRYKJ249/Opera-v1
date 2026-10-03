# Integrated Git and Cloud services

This directory contains the service code and configuration used by Opera.

- nextcloud/: Nextcloud source and configuration; live data and nested Git history are excluded.
- gitea/: Gitea configuration and supporting files; compiled binary and live data are excluded because GitHub rejects files over 100 MB and runtime data should not be versioned.
- gitea-migration/: Gitea migration assets.

The live services remain outside this repository at deployment time. Restore/install binaries and attach persistent database/storage separately.
