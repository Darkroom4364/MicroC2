package config

type Config struct {
	Storage struct {
		// Path is the local SQLite database used for durable server state.
		// It must live outside the web-served static directory.
		Path string `yaml:"path"`
	} `yaml:"storage"`

	Server struct {
		Port      string `yaml:"port"`
		HTTPSPort string `yaml:"httpsPort"`
		UploadDir string `yaml:"uploadDir"`
		StaticDir string `yaml:"staticDir"`
		TLS       struct {
			Enabled  bool   `yaml:"enabled"`
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
		} `yaml:"tls"`
		Redirect struct {
			Enabled  bool   `yaml:"enabled"`
			HTTPPort string `yaml:"httpPort"`
		} `yaml:"redirect"`
	} `yaml:"server"`

	Communication struct {
		Protocol    string `yaml:"protocol"`
		HTTPPolling struct {
			HeartbeatInterval int `yaml:"heartbeatInterval"`
		} `yaml:"http"`
	} `yaml:"communication"`

	Security struct {
		EnableCORS  bool     `yaml:"enableCORS"`
		CORSOrigins []string `yaml:"corsOrigins"`
		// OperatorToken protects the operator API and server terminal for
		// non-loopback clients. Empty means loopback-only operator access.
		// Can also be set via the MICROC2_OPERATOR_TOKEN environment variable.
		OperatorToken string `yaml:"operatorToken"`
		// OperatorAllowedOrigins lists origins allowed to call operator APIs
		// and open operator WebSockets (log stream, terminal). Same-host and
		// loopback origins are always allowed; "*" disables origin checks.
		OperatorAllowedOrigins []string `yaml:"operatorAllowedOrigins"`
	} `yaml:"security"`

	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`
}
