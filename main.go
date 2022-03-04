package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/oracle/oci-go-sdk/v50/common"
	"github.com/oracle/oci-go-sdk/v50/common/auth"
	"github.com/oracle/oci-go-sdk/v50/core"
)

var (
	version string
	commit  string
)

func main() {
	log.Println("Version: " + version)
	log.Println("Commit: " + commit)
	ctx, cancel := context.WithCancel(context.Background())
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
