package config

type Config struct {
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
	} `yaml:"security"`

	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`
}
