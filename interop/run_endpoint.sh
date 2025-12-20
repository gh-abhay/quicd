#!/bin/bash

set -eu

# set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

case $TESTCASE in
versionnegotiation|handshake|transfer|chacha20|keyupdate|retry|resumption|zerortt|http3|multiconnect|v2|rebind-port|rebind-addr|connectionmigration)
    :
;;
*)
    exit 127
;;
esac

if [ "$ROLE" == "client" ]; then
        exit 127
elif [ "$ROLE" == "server" ]; then
    echo "## Starting quicd server..."
    echo "## Server params: $SERVER_PARAMS"
    echo "## Test case: $TESTCASE"
    
    # Set file root to interop runner's WWW directory if provided
    if [ -n "${WWW:-}" ]; then
        echo "## Using WWW directory: $WWW"
        export QUICD_APPLICATIONS__HTTP3__CONFIG__HANDLER__FILE_ROOT="$WWW"
    fi
    
    /quicd -c /quicd.toml $SERVER_PARAMS
fi
