Example Leptos project with OAuth2 Client Support
=================================================

This project is built using [Leptos v0.4.5](https://github.com/leptos-rs/leptos) and uses [oauth2 = "4.4.1"](https://crates.io/crates/oauth2) crate as an OAuth2 client.

Review `.env.example` file for the configuration needed to run the project.

You may simple copy the file as `.env` and make the necessary updates to match your OAuth2 server configuration.

The example code provided only does the bare minimum of fetching a `access_code` and doesn't do any introspection and verification.
Those features will be added sometime in the future.
