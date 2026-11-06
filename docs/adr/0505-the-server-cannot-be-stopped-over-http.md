# The server cannot be stopped over HTTP

* Status: accepted
* Date: 2026-11-04

Technical Story: project analysis item G5

## Context and Problem Statement

`observability::admin_routes()` declared `POST /_merovingian/admin/shutdown` and `AdminOperation::shutdown`. Nothing
served it. When the declared operator routes were wired up (ADR-0504), should a request to stop the process be one of them?

## Decision Drivers

* The administrator token is a long-lived bearer credential on an HTTP surface. A stolen or phished one should not be
  able to take the server down.
* The operator already has the service manager (`systemctl stop`, `rc-service`, signals), which is authenticated by
  the operating system, logs who did it, and is what the packages configure.
* The process hardens itself (seccomp, privilege drop); a handler that exits the process is a second shutdown path
  that has to be kept in step with the signal path's graceful drain.

## Considered Options

* Serve it for administrators.
* Serve it only on the local socket surface.
* Remove the declaration, and serve nothing.

## Decision Outcome

Chosen option: "remove it". There is no shutdown route and no `AdminOperation::shutdown`. A request to
`/_merovingian/admin/shutdown` is a `404` under any method and with any token, and the test
`[g5]` "The server cannot be stopped over HTTP" asserts the server still serves afterwards.

Do not add it back as a convenience. If a restart is needed through the API, use the service manager.

## Links

* Related: [ADR-0504](0504-the-operator-route-table-is-the-only-list-of-operator-routes.md)
