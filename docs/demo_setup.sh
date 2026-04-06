#!/bin/sh
# Creates the demo project for the VHS recording.
# Called silently (Hide block) in docs/demo.tape.

rm -rf /tmp/sa-demo
mkdir -p /tmp/sa-demo/src /tmp/sa-demo/.github/workflows

# package.json with known-malicious axios@1.14.1
python3 -c "
import json, pathlib
pathlib.Path('/tmp/sa-demo/package.json').write_text(json.dumps({
    'name': 'my-app',
    'version': '1.0.0',
    'dependencies': {
        'axios': '1.14.1',
        'express': '^4.18.0'
    }
}, indent=2))
"

# src/api.js with a hardcoded Stripe secret key
cat > /tmp/sa-demo/src/api.js << 'EOF'
const axios  = require('axios');
const STRIPE = 'sk_live_51DEMO00000000000000000000';

async function fetchPayments() {
  return axios.get('https://api.stripe.com/v1/charges', {
    headers: { Authorization: `Bearer ${STRIPE}` }
  });
}

module.exports = { fetchPayments };
EOF

# CI config using npm install (not npm ci)
cat > /tmp/sa-demo/.github/workflows/ci.yml << 'EOF'
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm test
EOF
