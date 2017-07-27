package main

import (
	"cni-wrapper-plugin/adapter"
	"cni-wrapper-plugin/discover"
	"cni-wrapper-plugin/legacynet"
	"cni-wrapper-plugin/lib"
	"encoding/json"
	"errors"
	"fmt"
	"lib/datastore"
	"lib/filelock"
	"lib/rules"
	"lib/serial"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/coreos/go-iptables/iptables"
)

func cmdAdd(args *skel.CmdArgs) error {
	n, err := lib.LoadWrapperConfig(args.StdinData)
	if err != nil {
		return err
	}

	client := http.DefaultClient
	resp, err := client.Get(n.HealthCheckURL)
	if err != nil {
		return fmt.Errorf("could not call health check: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("health check failed with %d", resp.StatusCode))
	}

	pluginController, err := newPluginController(n.IPTablesLockFile)
	if err != nil {
		return err
	}

	var cniAddData struct {
		Metadata map[string]interface{}
	}
	if err := json.Unmarshal(args.StdinData, &cniAddData); err != nil {
		panic(err) // not tested, this should be impossible
	}

	app_id   := cniAddData.Metadata["app_id"]
	org_id   := cniAddData.Metadata["org_id"]
	space_id := cniAddData.Metadata["space_id"]
	policy_group_id := cniAddData.Metadata["policy_group_id"]
	
	cfAppLabel := map[string]string{"key": "app_id", "value": app_id}
    cfOrgLabel := map[string]string{"key": "org_id", "value": org_id}
    cfSpaceLabel := map[string]string{"key": "space_id", "value": space_id}
    cfPolicyGroupLabel := map[string]string{"key": "policy_group_id", "value": policy_group_id}
    
    cfLabels := make(map[string]interface{})
	cfLabels["labels"] = []interface{} { cfAppLabel, cfOrgLabel, cfSpaceLabel, cfPolicyGroupLabel }
    
    networkInfo := map[string]interface{} { "name": app_id, "labels" : cfLabels}
	networkInfoMap := map[string]interface{} { "network_info":networkInfo}
    
    // FIX ME
    TEMP_PLACE_HOLDER := "org.apache.mesos"
    argsMetadata := map[string]interface{}{ TEMP_PLACE_HOLDER: networkInfoMap }
    fmt.Printf("ArgsMetadata is : %+v\n", ArgsMetadata)

	jsonString, _ := json.Marshal(argsMetadata)
	fmt.Println("Passed Args Metadata: %s", string(jsonString))
		
	n.Delegate["args"] = argsMetadata
	result, err := pluginController.DelegateAdd(n.Delegate)
	if err != nil {
		return fmt.Errorf("delegate call: %s", err)
	}

	result030, err := current.NewResultFromResult(result)
	if err != nil {
		return fmt.Errorf("converting result from delegate plugin: %s", err) // not tested
	}

	containerIP := result030.IPs[0].Address.IP

	// Add container metadata info
	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker:     filelock.NewLocker(n.Datastore),
	}

	if err := store.Add(args.ContainerID, containerIP.String(), cniAddData.Metadata); err != nil {
		storeErr := fmt.Errorf("store add: %s", err)
		fmt.Fprintf(os.Stderr, "%s", storeErr)
		fmt.Fprintf(os.Stderr, "cleaning up from error")
		err = pluginController.DelIPMasq(containerIP.String(), n.VTEPName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "during cleanup: removing IP masq: %s", err)
		}

		return storeErr
	}

	// Initialize dns
	var localDNSServers []string
	for _, entry := range n.DNSServers {
		dnsIP := net.ParseIP(entry)
		if dnsIP == nil {
			return fmt.Errorf(`invalid DNS server "%s", must be valid IP address`, entry)
		} else if dnsIP.IsLinkLocalUnicast() {
			localDNSServers = append(localDNSServers, entry)
		}
	}

	defaultInterface := discover.DefaultInterface{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
		NetAdapter:     &adapter.NetAdapter{},
	}
	defaultIfaceName, err := defaultInterface.Name()
	if err != nil {
		return fmt.Errorf("discover default interface name: %s", err) // not tested
	}

	// Initialize NetOut
	netOutProvider := legacynet.NetOut{
		ChainNamer: &legacynet.ChainNamer{
			MaxLength: 28,
		},
		IPTables:          pluginController.IPTables,
		Converter:         &legacynet.NetOutRuleConverter{Logger: os.Stderr},
		ASGLogging:        n.IPTablesASGLogging,
		C2CLogging:        n.IPTablesC2CLogging,
		DeniedLogsPerSec:  n.IPTablesDeniedLogsPerSec,
		IngressTag:        n.IngressTag,
		VTEPName:          n.VTEPName,
		HostInterfaceName: defaultIfaceName,
	}
	if err := netOutProvider.Initialize(args.ContainerID, containerIP, localDNSServers); err != nil {
		return fmt.Errorf("initialize net out: %s", err)
	}

	// Initialize NetIn
	netinProvider := legacynet.NetIn{
		ChainNamer: &legacynet.ChainNamer{
			MaxLength: 28,
		},
		IPTables:          pluginController.IPTables,
		IngressTag:        n.IngressTag,
		HostInterfaceName: defaultIfaceName,
	}
	err = netinProvider.Initialize(args.ContainerID)

	// Create port mappings
	portMappings := n.RuntimeConfig.PortMappings
	for _, netIn := range portMappings {
		if netIn.HostPort <= 0 {
			return fmt.Errorf("cannot allocate port %d", netIn.HostPort)
		}
		if err := netinProvider.AddRule(args.ContainerID, int(netIn.HostPort), int(netIn.ContainerPort), n.InstanceAddress, containerIP.String()); err != nil {
			return fmt.Errorf("adding netin rule: %s", err)
		}
	}

	// Create egress rules
	netOutRules := n.RuntimeConfig.NetOutRules
	if err := netOutProvider.BulkInsertRules(args.ContainerID, netOutRules); err != nil {
		return fmt.Errorf("bulk insert: %s", err) // not tested
	}

	err = pluginController.AddIPMasq(containerIP.String(), n.VTEPName)
	if err != nil {
		return fmt.Errorf("error setting up default ip masq rule: %s", err)
	}

	result030.DNS.Nameservers = n.DNSServers
	return result030.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := lib.LoadWrapperConfig(args.StdinData)
	if err != nil {
		return err
	}

	store := &datastore.Store{
		Serializer: &serial.Serial{},
		Locker:     filelock.NewLocker(n.Datastore),
	}

	container, err := store.Delete(args.ContainerID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store delete: %s", err)
	}

	pluginController, err := newPluginController(n.IPTablesLockFile)
	if err != nil {
		return err
	}

	if err := pluginController.DelegateDel(n.Delegate); err != nil {
		fmt.Fprintf(os.Stderr, "delegate delete: %s", err)
	}

	netInProvider := legacynet.NetIn{
		ChainNamer: &legacynet.ChainNamer{
			MaxLength: 28,
		},
		IPTables:   pluginController.IPTables,
		IngressTag: n.IngressTag,
	}

	if err = netInProvider.Cleanup(args.ContainerID); err != nil {
		fmt.Fprintf(os.Stderr, "net in cleanup: %s", err)
	}

	defaultInterface := discover.DefaultInterface{
		NetlinkAdapter: &adapter.NetlinkAdapter{},
		NetAdapter:     &adapter.NetAdapter{},
	}
	defaultIfaceName, err := defaultInterface.Name()
	if err != nil {
		return fmt.Errorf("discover default interface name: %s", err) // not tested
	}

	netOutProvider := legacynet.NetOut{
		ChainNamer: &legacynet.ChainNamer{
			MaxLength: 28,
		},
		IPTables:          pluginController.IPTables,
		Converter:         &legacynet.NetOutRuleConverter{Logger: os.Stderr},
		HostInterfaceName: defaultIfaceName,
	}

	if err = netOutProvider.Cleanup(args.ContainerID, container.IP); err != nil {
		fmt.Fprintf(os.Stderr, "net out cleanup: %s", err)
	}

	err = pluginController.DelIPMasq(container.IP, n.VTEPName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "removing IP masq: %s", err)
	}

	return nil
}

func newPluginController(iptablesLockFile string) (*lib.PluginController, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	iptLocker := &rules.IPTablesLocker{
		FileLocker: filelock.NewLocker(iptablesLockFile),
		Mutex:      &sync.Mutex{},
	}
	restorer := &rules.Restorer{}
	lockedIPTables := &rules.LockedIPTables{
		IPTables: ipt,
		Locker:   iptLocker,
		Restorer: restorer,
	}

	pluginController := &lib.PluginController{
		Delegator: lib.NewDelegator(),
		IPTables:  lockedIPTables,
	}
	return pluginController, nil
}

func main() {
	supportedVersions := []string{"0.3.1"}

	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports(supportedVersions...))
}
