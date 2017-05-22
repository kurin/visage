# visage

[![GoDoc](https://godoc.org/github.com/kurin/visage?status.svg)](https://godoc.org/github.com/kurin/visage)

Visage is a library that allows services to share file content over the web.
It can be integrated directly with existing programs or run as a standalone
package.  

## Integration

The `visage` package can be used to add the ability to share files based on
arbitrary credentials.  Application authors can implement a type that satisfies
the `FileSystem` interface (or use the provided `Directory` type, for local
file system access) and then selectively allow access.

## Standalone

The standalone binary included in this repository serves as a proof-of-concept
implementation.  It provides a simple web interface that allows one or more
administrators to create shares and assign share ownership to others, who can
themselves share individual files or directories with third parties as they
please.

---

This is not an official Google product.
