# Hermes Dashboard contract

This directory will freeze the Hermes Dashboard surface that each Hermternal release supports.

The contract will cover selected REST routes, authentication behavior, WebSocket ticket creation, WebSocket messages, chat events, error forms, and compatibility metadata. It will pin evidence to a reviewed Hermes source revision because parts of the dashboard protocol are source-defined rather than a stable public API.

A contract change must include redacted fixtures and matching web and Apple compatibility tests. This directory does not contain a client implementation or a live server connection.
