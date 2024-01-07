# unifi-discover

Tool to discover Unifi devices in a local network. It works by sending a broadcast UDP packet to port 10001.

You need a recent Go toolchain.

Just run `go build`, then `./unifi-discover --help`.
You probably just want to run `unifi-discover --json | jq`.

For a Python implementation see https://github.com/nitefood/python-ubnt-discovery 
