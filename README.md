# unifidiscover

Tool and library to discover Unifi devices in a local network. It works by sending a broadcast UDP packet to port 10001.

You need a recent Go toolchain.

Either use the library under the root of the repository, or che CLI under `cmd/unifi-discover`.
Build it with `go build`, then run `./unifi-discover --help`.
You probably just want to run `unifi-discover --json | jq`.

For a Python implementation see https://github.com/nitefood/python-ubnt-discovery 
