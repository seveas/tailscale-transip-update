package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/transip/gotransip/v6"
	tipdomain "github.com/transip/gotransip/v6/domain"
	"tailscale.com/client/tailscale"
)

var rootCmd = &cobra.Command{
	Use:     "tailscale-transip-update",
	Long:    "Update DNS records for tailscale nodes in a transip-hosted domain",
	Example: "tailscale-transip-update --domain seve.as --key ~/transip.key",
	Args:    cobra.NoArgs,
	Version: "1.0",
	Run:     run,
}

func init() {
	cobra.OnInitialize(func() {
		if dir, err := homedir.Dir(); err == nil {
			viper.AddConfigPath(filepath.Join(dir, ".config", "tailscale-transip-update"))
			viper.SetConfigName("config")
			if err := viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					bail("Can't read configuration: %s", err)
				}
			}
		}
		viper.SetEnvPrefix("TAILSCALE_TRANSIP_UPDATE")
		viper.AutomaticEnv()
		if viper.GetBool("Verbose") {
			log.SetLevel(log.DebugLevel)
		}
	})
	rootCmd.Flags().StringP("user", "u", "", "TransIP user account")
	rootCmd.Flags().StringP("key", "k", "", "TransIP API private key")
	rootCmd.Flags().StringP("domain", "d", "", "Which domain the records should be updated under")
	rootCmd.Flags().StringP("subdomain", "s", "", "Which subdomain the records should be updated under")
	rootCmd.Flags().DurationP("expire", "e", time.Hour, "Expiry for new records")
	rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")

	viper.BindPFlag("User", rootCmd.Flags().Lookup("user"))
	viper.BindPFlag("Key", rootCmd.Flags().Lookup("key"))
	viper.BindPFlag("Domain", rootCmd.Flags().Lookup("domain"))
	viper.BindPFlag("Subdomain", rootCmd.Flags().Lookup("subdomain"))
	viper.BindPFlag("Expire", rootCmd.Flags().Lookup("expire"))
	viper.BindPFlag("Verbose", rootCmd.Flags().Lookup("verbose"))
}

func main() {
	rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	user := viper.GetString("User")
	key, _ := homedir.Expand(viper.GetString("Key"))
	domain := strings.Trim(viper.GetString("Domain"), ".")
	sub := strings.Trim(strings.TrimSuffix(strings.Trim(viper.GetString("SubDomain"), "."), domain), ".")
	if sub != "" {
		sub = "." + sub
	}
	expire := viper.GetDuration("Expire")

	status, err := tailscale.Status(context.Background())
	if err != nil {
		bail("unable to read tailscale status: %s", err)
	}
	status.Peer[status.Self.PublicKey] = status.Self

	log.Debugf("Logging in as user %s with the key in %s", user, key)

	client, err := gotransip.NewClient(gotransip.ClientConfiguration{
		AccountName:    user,
		PrivateKeyPath: key,
	})
	if err != nil {
		bail("login failed: %s", err)
	}
	repo := &tipdomain.Repository{Client: client}
	entries, err := repo.GetDNSEntries(domain)
	if err != nil {
		bail("unable to retrieve dns entries for %s: %s", domain, err)
	}
	for _, peer := range status.Peer {
		if peer.DNSName == "" {
			continue
		}
		name := peer.DNSName[:strings.IndexRune(peer.DNSName, '.')] + sub
		log.Debugf("Updating records for %s.%s", name, domain)
		for _, ip := range peer.TailscaleIPs {
			addr := ip.String()
			typ := "A"
			if ip.Is6() {
				typ = "AAAA"
			}
			found := false
			for _, entry := range entries {
				if entry.Name == name && entry.Type == typ {
					found = true
					if entry.Content == addr {
						log.Debugf("%s record for %s.%s has not changed", typ, name, domain)
					} else {
						log.Infof("updating %s record for %s.%s from %s to %s", typ, name, domain, entry.Content, addr)
						entry.Content = addr
						err := repo.UpdateDNSEntry(domain, entry)
						if err != nil {
							bail("Unable to update %s record for %s: %s", typ, name, err)
						}
					}
				}
			}
			if !found {
				log.Infof("adding %s record for %s.%s pointing to %s", typ, name, domain, addr)
				err := repo.AddDNSEntry(domain, tipdomain.DNSEntry{Name: name, Expire: int(expire / time.Second), Type: typ, Content: addr})
				if err != nil {
					bail("Unable to add %s record for %s: %s", typ, name, err)
				}
			}
		}
	}
	_ = client

}

func bail(format string, args ...interface{}) {
	log.Errorf(format, args...)
	os.Exit(1)
}
