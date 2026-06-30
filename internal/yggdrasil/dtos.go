// Package yggdrasil contains protocol handlers and data transfer objects for the Yggdrasil specification.
package yggdrasil

// metaMeta holds the server and implementation identity embedded in the authlib-injector metadata document.
type metaMeta struct {
	ServerName            string     `json:"serverName"`
	ImplementationName    string     `json:"implementationName"`
	ImplementationVersion string     `json:"implementationVersion"`
	Links                 *metaLinks `json:"links,omitempty"`
	// EnableProfileKey signals to authlib-injector clients that this server supports
	// the player certificates endpoint (MC 1.19+ signed chat). The dotted JSON key
	// is required by the authlib-injector feature flag convention.
	EnableProfileKey bool `json:"feature.enable_profile_key"`
}

// metaLinks holds optional launcher-facing URLs advertised in the authlib-injector
// metadata document. Homepage points to the server root; Register points to the
// page where new accounts are created.
type metaLinks struct {
	Homepage string `json:"homepage,omitempty"`
	Register string `json:"register,omitempty"`
}

// MetadataResponse is the root document served at GET / for authlib-injector clients.
// Ref: https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-服务端技术规范
type MetadataResponse struct {
	Meta               metaMeta `json:"meta"`
	SkinDomains        []string `json:"skinDomains"`
	SignaturePublickey string   `json:"signaturePublickey"`
}

// agentField is the optional Minecraft game agent descriptor sent by launchers during authenticate.
type agentField struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// AuthenticateRequest is the request body for POST /authserver/authenticate.
type AuthenticateRequest struct {
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	ClientToken string      `json:"clientToken"`
	Agent       *agentField `json:"agent"`
	RequestUser bool        `json:"requestUser"`
}

// ProfileStub is the minimal profile shape used in availableProfiles and selectedProfile.
// The id field is always the undashed 32-hex UUID as required by the Yggdrasil wire format.
type ProfileStub struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserProperty is a single key-value metadata entry on a user object.
type UserProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// UserResponse is the user object returned in authenticate/refresh when requestUser is true.
type UserResponse struct {
	ID         string         `json:"id"`
	Properties []UserProperty `json:"properties"`
}

// AuthenticateResponse is the response body for POST /authserver/authenticate.
type AuthenticateResponse struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	AvailableProfiles []ProfileStub `json:"availableProfiles"`
	SelectedProfile   *ProfileStub  `json:"selectedProfile,omitempty"`
	User              *UserResponse `json:"user,omitempty"`
}

// RefreshRequest is the request body for POST /authserver/refresh.
type RefreshRequest struct {
	AccessToken     string       `json:"accessToken"`
	ClientToken     string       `json:"clientToken"`
	SelectedProfile *ProfileStub `json:"selectedProfile"`
	RequestUser     bool         `json:"requestUser"`
}

// RefreshResponse is the response body for POST /authserver/refresh.
type RefreshResponse struct {
	AccessToken     string        `json:"accessToken"`
	ClientToken     string        `json:"clientToken"`
	SelectedProfile *ProfileStub  `json:"selectedProfile,omitempty"`
	User            *UserResponse `json:"user,omitempty"`
}

// ValidateRequest is the request body for POST /authserver/validate.
type ValidateRequest struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

// InvalidateRequest is the request body for POST /authserver/invalidate.
type InvalidateRequest struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

// SignoutRequest is the request body for POST /authserver/signout.
type SignoutRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JoinRequest is the request body for POST /sessionserver/session/minecraft/join.
type JoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"` // undashed 32-hex UUID
	ServerID        string `json:"serverId"`
}

// TextureProperty is a signed or unsigned profile property in the full profile response.
// The Signature field is omitted when the caller requests an unsigned profile.
type TextureProperty struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
}

// FullProfile is the complete profile object returned by hasJoined and the profile endpoint.
type FullProfile struct {
	ID         string            `json:"id"` // undashed 32-hex UUID
	Name       string            `json:"name"`
	Properties []TextureProperty `json:"properties"`
}

// YggError is the Yggdrasil protocol error envelope.
// Ref: https://minecraft.wiki/w/Yggdrasil#Errors
type YggError struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
	Cause        string `json:"cause,omitempty"`
}
