package config

type Config struct {
	Storage struct {
		// Path is the local SQLite database used for durable server state.
		// It must live outside the web-served static directory.
		Path string `yaml:"path"`
	} `yaml:"storage"`

	Server struct {
		// Port is the sole HTTPS port for the operator UI and API.
		Port      string `yaml:"port"`
		UploadDir string `yaml:"uploadDir"`
		StaticDir string `yaml:"staticDir"`
		TLS       struct {
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
		} `yaml:"tls"`
		Redirect struct {
			Enabled  bool   `yaml:"enabled"`
			HTTPPort string `yaml:"httpPort"`
		} `yaml:"redirect"`
	} `yaml:"server"`

	Security struct {
		// EnableServerTerminal permits the browser-accessible shell on the
		// server host. Its secure default is false.
		EnableServerTerminal bool     `yaml:"enableServerTerminal"`
		CORSOrigins          []string `yaml:"corsOrigins"`
		AgentTransport       struct {
			// AllowInsecureIsolatedLab permits plaintext HTTP agent listeners.
			// The secure production default is false.
			AllowInsecureIsolatedLab bool `yaml:"allowInsecureIsolatedLab"`
		} `yaml:"agentTransport"`
		// OperatorToken protects the operator API and, when explicitly enabled,
		// the server terminal for non-loopback clients. Empty means
		// loopback-only operator access.
		// Can also be set via the MICROC2_OPERATOR_TOKEN environment variable.
		OperatorToken string `yaml:"operatorToken"`
		// OperatorAllowedOrigins lists origins allowed to call operator APIs
		// and open operator WebSockets (log stream, terminal). The exact
		// same origin is always allowed; "*" disables origin checks.
		OperatorAllowedOrigins []string `yaml:"operatorAllowedOrigins"`
	} `yaml:"security"`

	Logging struct {
		File string `yaml:"file"`
	} `yaml:"logging"`
}
