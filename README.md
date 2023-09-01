# Rust Vercel Blob Client

This crate contains a rust client for working with the [Vercel Blob API].
The client can be used both inside your application (for example, a serverless
function using the [rust runtime] and outside your application (for example,
a rust-based file upload client)

[Vercel Blob API]: https://vercel.com/docs/storage/vercel-blob
[rust runtime]: https://github.com/vercel-community/rust

## Authentication

### Within your application

If your rust code is part of a rust serverless function then authentication is automatic
and provided as a part of the vercel runtime.

### Outside your application

If your rust code is part of a client package (running in the browser via wasm or running
some kind of custom client application) then you will need to obtain an authentication
token. This can be done by creating a route in your server that will supply short-lived
authentication tokens to authorized users.  The crate documentation contains an example.
