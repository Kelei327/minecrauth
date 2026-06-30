// SPDX-License-Identifier: Apache-2.0

package openapi

import _ "embed"

// SpecJSON contains the raw bytes of the generated OpenAPI 3.1 JSON specification.
//
//go:embed swagger.json
var SpecJSON []byte

// SpecYAML contains the raw bytes of the generated OpenAPI 3.1 YAML specification.
//
//go:embed swagger.yaml
var SpecYAML []byte
