
echo "Setting up Nuke403 environment..."
python3 -m venv nuke403-env
source nuke403-env/bin/activate
pip install -r requirements.txt

mkdir -p core/profiler/signatures
mkdir -p core/ai_core/models
mkdir -p payloads/fuzz_dictionaries
mkdir -p config/target_lists
mkdir -p tests/unit_tests
mkdir -p tests/live_targets

echo "Downloading pre-trained models..."
if [ ! -f core/profiler/signatures/cloudflare_signatures.json ]; then
    echo "Creating default signature files..."
    cp examples/signatures/cloudflare_signatures.json core/profiler/signatures/
    cp examples/signatures/nginx_signatures.json core/profiler/signatures/
    cp examples/signatures/aws_waf_signatures.json core/profiler/signatures/
    cp examples/signatures/backend_signatures.json core/profiler/signatures/
fi

if [ ! -f payloads/path_bypasses.json ]; then
    echo "Creating default payload files..."
    cp examples/payloads/path_bypasses.json payloads/
    cp examples/payloads/header_bypasses.json payloads/
    cp examples/payloads/protocol_bypasses.json payloads/
fi

echo "Setup complete! Activate the environment with: source nuke403-env/bin/activate"