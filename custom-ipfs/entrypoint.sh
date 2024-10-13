#!/bin/sh
set -e

# Initialize IPFS if it hasn't been initialized yet
if [ ! -d "/data/ipfs" ]; then
    ipfs init --profile=lowpower
fi

# Set CORS configuration
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'  # or specify domains like '["http://localhost:8080"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["PUT", "POST", "GET"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Credentials '["true"]'

# Start the IPFS daemon
exec ipfs daemon --migrate=true
