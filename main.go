package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/creativeprojects/go-selfupdate"
	"github.com/oracle/oci-go-sdk/v50/common"
	"github.com/oracle/oci-go-sdk/v50/common/auth"
	"github.com/oracle/oci-go-sdk/v50/core"
)

var (
	version       string
	commit        string
	DisableUpdate bool = os.Getenv("DISABLE_UPDATE") == "true"
)

func doSelfUpdate() {
	selfupdate.SetLogger(log.Default()) // enable when debug logging is needed
	updater, err := selfupdate.NewUpdater(selfupdate.Config{Validator: &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"}})
	log.Printf("Error finding latest version: %v\n", err)
	if DisableUpdate {
		latest, found, err := updater.DetectLatest("rtdev7690/dns-whitelist")
		if err != nil {
			log.Printf("Error finding latest version: %v\n", err)
			return
		}
		if found {
			log.Println("Found latest version: ", latest)
		} else {
			log.Println("Couldn't find latest version")
		}

		return
	}

	latest, err := updater.UpdateSelf(version, "rtdev7690/dns-whitelist")
	if err != nil {
		log.Println("Binary update failed:", err)
		return
	}
	log.Println("Latest version: ", latest.Version())
	if latest.Equal(version) {
		// latest version is the same as current version. It means current binary is up to date.
		log.Println("Current binary is the latest version", version)
	} else {
		log.Println("Successfully updated to version", latest.Version())
		log.Println("Release note:\n", latest.ReleaseNotes)
		log.Println("Exiting.")
		os.Exit(0)
	}
}

func main() {
	log.Println("Version: " + version)
	log.Println("Commit: " + commit)
	ctx, cancel := context.WithCancel(context.Background())
	doSelfUpdate()

	addrs, err := net.LookupHost(os.Getenv("DNS_RECORD"))
	if err != nil {
		log.Fatal(err)
	}

	if len(addrs) == 0 {
		log.Fatal("Failed to resolve addresses")
	}

	log.Printf("%v", addrs)

	provider := common.DefaultConfigProvider()

	if os.Getenv("LOCAL") == "" {
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			log.Fatal(err)
		}
	}

	oci, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)

	if err != nil {
		log.Fatal(err)
	}

	policy := common.DefaultRetryPolicy()

	resp, err := oci.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		RequestMetadata:        common.RequestMetadata{RetryPolicy: &policy},
	})

	if err != nil {
		log.Fatal(err)
	}

	portMap := map[int]bool{80: true, 443: true, 7000: true}
	var updatedRules = make([]core.UpdateSecurityRuleDetails, 0)

	for i := range resp.Items {
		item := resp.Items[i]
		if item.TcpOptions != nil && portMap[*item.TcpOptions.DestinationPortRange.Min] {
			item.Source = common.String(addrs[0] + "/32")
			updatedRules = append(updatedRules, core.UpdateSecurityRuleDetails{
				Direction:       core.UpdateSecurityRuleDetailsDirectionEnum(item.Direction),
				Id:              item.Id,
				Protocol:        item.Protocol,
				Description:     item.Description,
				Destination:     item.Destination,
				DestinationType: core.UpdateSecurityRuleDetailsDestinationTypeEnum(item.DestinationType),
				IsStateless:     item.IsStateless,
				Source:          item.Source,
				SourceType:      core.UpdateSecurityRuleDetailsSourceTypeEnum(item.SourceType),
				TcpOptions:      item.TcpOptions,
			})
		}
	}

	_, err = oci.UpdateNetworkSecurityGroupSecurityRules(ctx, core.UpdateNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		UpdateNetworkSecurityGroupSecurityRulesDetails: core.UpdateNetworkSecurityGroupSecurityRulesDetails{
			SecurityRules: updatedRules,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
	log.Println("Updated rules")
	cancel()
}
