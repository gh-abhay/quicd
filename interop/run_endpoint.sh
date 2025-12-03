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
    echo "## Starting quiche server..."
    echo "## Server params: $SERVER_PARAMS"
    echo "## Test case: $TESTCASE"
    /quicd -c /quicd.toml $SERVER_PARAMS
fi
