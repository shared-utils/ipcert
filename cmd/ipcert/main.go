package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alecthomas/kong"

	"github.com/shared-utils/ipcert/internal/cert"
)

type ZeroSSLConfig struct {
	ApiKey  string `help:"ZeroSSL API Key" env:"ZEROSSL_API_KEY" name:"api-key" required:""`
	BaseURL string `help:"ZeroSSL API Base URL" env:"ZEROSSL_BASE_URL" default:"https://api.zerossl.com" name:"base-url"`
}

type Options struct {
	ZeroSSL   ZeroSSLConfig `embed:"" prefix:"zerossl."`
	OutputDir string        `help:"Output directory for certificates" type:"path" default:"/etc/ipcert" name:"output-dir"`
	PublicIPs []string      `help:"Public IPs (comma separated)" env:"PUBLIC_IPS" sep:"," name:"public-ips" required:""`
	Timeout   time.Duration `help:"Timeout for certificate operations" default:"2m" name:"timeout"`
}

func (o *Options) newManager() (cert.Manager, error) {
	return cert.NewManager(cert.Config{
		CertDir:          o.OutputDir,
		CertValidityDays: 90,
		ZeroSSLApiKey:    o.ZeroSSL.ApiKey,
		ZeroSSLBaseURL:   o.ZeroSSL.BaseURL,
		PublicIps:        o.PublicIPs,
	})
}

func (o *Options) obtain(m cert.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
	defer cancel()
	return m.Obtain(ctx)
}

type EnsureCmd struct {
	Options
}

func (e *EnsureCmd) Run() error {
	m, err := e.newManager()
	if err != nil {
		return err
	}

	c, _ := m.Load()
	if c != nil && time.Until(c.NotAfter).Hours() > 48 {
		fmt.Printf("Certificate valid (expires in %.0f days)\n", time.Until(c.NotAfter).Hours()/24)
		return nil
	}

	fmt.Println("Requesting certificate...")
	if err := e.obtain(m); err != nil {
		return err
	}
	fmt.Println("Certificate obtained successfully.")
	return nil
}

type RenewCmd struct {
	Options
}

func (r *RenewCmd) Run() error {
	m, err := r.newManager()
	if err != nil {
		return err
	}

	fmt.Printf("Requesting certificate for IPs: %v\n", r.PublicIPs)
	if err := r.obtain(m); err != nil {
		return err
	}
	fmt.Println("Certificate obtained successfully.")
	return nil
}

type CLI struct {
	Ensure EnsureCmd `cmd:"" help:"Ensure certificates are available for public IPs"`
	Renew  RenewCmd  `cmd:"" help:"Force request new certificates regardless of existence"`
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("ipcert"),
		kong.Description("IP certificate generator using ZeroSSL"),
		kong.UsageOnError(),
	)
	if err := ctx.Run(); err != nil {
		log.Fatal(err)
	}
}
