package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/creativeprojects/go-selfupdate"
	"github.com/oracle/oci-go-sdk/v50/common"
	"github.com/oracle/oci-go-sdk/v50/common/auth"
	"github.com/oracle/oci-go-sdk/v50/core"
)

var (
	version         string
	commit          string
	DisableUpdate   bool   = os.Getenv("DISABLE_UPDATE") == "true"
	DisableChecking bool   = os.Getenv("DISABLE_CHECKS") == "true"
	provider        string = os.Getenv("PROVIDER")
	dnsRecord       string = os.Getenv("DNS_RECORD")
	listID          string = os.Getenv("LIST_ID")
	accountID       string = os.Getenv("ACCOUNT_ID")
)

func doSelfUpdate() {
	if DisableChecking {
		return
	}
	selfupdate.SetLogger(log.Default()) // enable when debug logging is needed
	updater, err := selfupdate.NewUpdater(selfupdate.Config{Validator: &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"}})
	if err != nil {
		log.Printf("Error creating updater: %v\n", err)
		return
	}

	if DisableUpdate {
		latest, found, lerr := updater.DetectLatest("rtdev7690/dns-whitelist")
		if lerr != nil {
			log.Printf("Error finding latest version: %v\n", lerr)
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

// O(N) contains check for cloudflare ip slices. Use sets or maps to optimize when possible
func contains(elems []cloudflare.IPListItem, v string) bool {
	for i := range elems {
		if elems[i].IP == v {
			return true
		}
	}
	return false
}

// O(N) contains check for strings. Use sets or maps to optimize when possible
func containsString(elems []string, v string) bool {
	for i := range elems {
		if elems[i] == v {
			return true
		}
	}
	return false
}

func whitelistCloudflare(ctx context.Context) error {
	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"), cloudflare.UsingAccount(accountID))
	if err != nil {
		return err
	}

	list, err := api.ListIPListItems(ctx, listID)
	if err != nil {
		return err
	}

	records := strings.Split(dnsRecord, ";")

	if len(records) == 0 {
		return errors.New("no dns records set to resolve")
	}

	var ips = make([]string, 0)

	for i := range records {
		addrs, err := net.LookupHost(records[i])
		if err != nil {
			return err
		}
		ips = append(ips, addrs...)
	}
	log.Println("desired ips: ", ips)

	var toAdd []cloudflare.IPListItemCreateRequest
	var toDelete []cloudflare.IPListItemDeleteItemRequest

	for i := range ips {
		// if the desired ip isn't in the existing list add it
		if !contains(list, ips[i]) {
			toAdd = append(toAdd, cloudflare.IPListItemCreateRequest{IP: ips[i]})
		}
	}
	for i := range list {
		// if an item exists that isnt in the desired list, delete it.
		if !containsString(ips, list[i].IP) {
			toDelete = append(toDelete, cloudflare.IPListItemDeleteItemRequest{ID: list[i].ID})
		}
	}

	log.Println("toAdd: ", toAdd, " toDelete: ", toDelete)

	if len(toAdd) != 0 {
		_, err := api.CreateIPListItems(ctx, listID, toAdd)
		if err != nil {
			return err
		}
	}
	if len(toDelete) != 0 {
		_, err := api.DeleteIPListItems(ctx, listID, cloudflare.IPListItemDeleteRequest{Items: toDelete})
		if err != nil {
			return err
		}
	}

	return nil
}

func whitelistOCI(ctx context.Context) error {
	addrs, err := net.LookupHost(dnsRecord)
	if err != nil {
		return err
	}

	if len(addrs) == 0 {
		return errors.New("failed to resolve addresses")
	}

	log.Printf("%v", addrs)

	provider := common.DefaultConfigProvider()

	if os.Getenv("LOCAL") == "" {
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return err
		}
	}

	oci, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)

	if err != nil {
		return err
	}

	policy := common.DefaultRetryPolicy()

	resp, err := oci.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		RequestMetadata:        common.RequestMetadata{RetryPolicy: &policy},
	})

	if err != nil {
		return err
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
	return err
}

func main() {
	log.Println("Version: " + version)
	log.Println("Commit: " + commit)
	ctx, cancel := context.WithCancel(context.Background())
	doSelfUpdate()

	var err error
	switch provider {
	case "OCI":
		err = whitelistOCI(ctx)
	case "Cloudflare":
		err = whitelistCloudflare(ctx)
	default:
		err = errors.New("unsupported provider: " + provider)
	}

	if err != nil {
		log.Fatal(err)
	}
	log.Println("Updated rules")
	cancel()
}
