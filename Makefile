SHELL := /bin/bash

# The versions of the Kubescape data and the test resources, shared with the installer script.
# Evaluated when a download target runs, so that building needs no jq.
data_sources = scripts/data-sources.json
cel_version = $(shell jq -r .celAdmissionLibrary $(data_sources))
rego_version = $(shell jq -r .regolibrary $(data_sources))
vap_test_files = $(shell jq -r '.vapTestFiles[]' $(data_sources))

PYTHON ?= python3

.PHONY: wasm-download kubescape-cel-admission-library-download kubescape-rego-download download build local

# wasm_exec.js must come from the Go release that builds main.wasm, so it is copied from
# the toolchain selected by go/go.mod instead of being downloaded.
wasm-download:
	cp "$$(go -C go env GOROOT)/lib/wasm/wasm_exec.js" src/wasm/wasm_exec.js

kubescape-cel-admission-library-download:
	mkdir -p public
	curl -fL https://github.com/kubescape/cel-admission-library/releases/download/$(cel_version)/basic-control-configuration.yaml -o public/basic-control-configuration.yaml
	curl -fL https://github.com/kubescape/cel-admission-library/releases/download/$(cel_version)/kubescape-validating-admission-policies.yaml -o public/validating-admission-policies.yaml
	rm -f public/vap-test-files*
	set -o pipefail; for word in ${vap_test_files}; do \
		printf '\n---\n' >> public/vap-test-files.yaml; \
		curl -fL https://raw.githubusercontent.com/kubescape/cel-admission-library/$(cel_version)/test-resources/$$word >> public/vap-test-files.yaml || exit 1; \
		echo $$word >> public/vap-test-files-index.yaml; \
	done

kubescape-rego-download:
	mkdir -p public
	set -o pipefail; curl -fL https://github.com/kubescape/regolibrary/releases/download/$(rego_version)/frameworks \
	    | jq '.[].controls = []' > public/frameworks.json
	curl -fL https://github.com/kubescape/regolibrary/releases/download/$(rego_version)/controls \
	    -o public/controls.json
	curl -fL https://github.com/kubescape/regolibrary/releases/download/$(rego_version)/rules \
	    -o public/rego-rules.json

download: wasm-download kubescape-cel-admission-library-download kubescape-rego-download

build:
	GOOS=js GOARCH=wasm go -C go build -ldflags="-s -w" -o ../dist/main.wasm cmd/main.go

# Builds a copy of this checkout (main.js, package.json, main.wasm and the Kubescape data) and
# installs it into Headlamp desktop on Linux, macOS or Windows; on Windows use PYTHON=py.
local:
	$(PYTHON) scripts/install_headlamp_plugin.py --source .
