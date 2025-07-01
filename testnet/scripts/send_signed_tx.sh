#!/bin/bash

# send_signed_tx.sh - Helper script to send signed transactions using cast
# This is an alternative approach that doesn't require unlocked accounts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if cast is available
if ! command -v cast &> /dev/null; then
    echo "cast command not found. Please install foundry: https://getfoundry.sh/"
    exit 1
fi

# Test account private key (well-known test key)
TEST_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Function to send signed transaction
send_signed_transaction() {
    local rpc_url=$1
    local to_address=$2
    local value=$3
    local chain_id=${4:-1337}  # Default chain ID
    
    # Use cast to send the transaction
    cast send \
        --rpc-url "$rpc_url" \
        --private-key "$TEST_PRIVATE_KEY" \
        --value "$value" \
        "$to_address" \
        --json 2>/dev/null | jq -r '.transactionHash' 2>/dev/null || echo ""
}

# If called directly with arguments
if [ $# -ge 3 ]; then
    send_signed_transaction "$@"
fi