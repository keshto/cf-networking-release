package main_test

import (
	"cni-wrapper-plugin/lib"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"

	"code.cloudfoundry.org/garden"

	noop_debug "github.com/containernetworking/cni/plugins/test/noop/debug"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/pivotal-cf-experimental/gomegamatchers"
	"github.com/vishvananda/netlink"
)

type InputStruct struct {
	Name       string                 `json:"name"`
	CNIVersion string                 `json:"cniVersion"`
	Type       string                 `json:"type"`
	Delegate   map[string]interface{} `json:"delegate"`
	Metadata   map[string]interface{} `json:"metadata"`
	lib.WrapperConfig
}

var _ = Describe("CniWrapperPlugin", func() {

	var (
		cmd                     *exec.Cmd
		debugFileName           string
		datastorePath           string
		iptablesLockFilePath    string
		input                   string
		debug                   *noop_debug.Debug
		healthCheckServer       *httptest.Server
		healthCheckReturnStatus int
		inputStruct             InputStruct
		containerID             string
		netinChainName          string
		netoutChainName         string
		inputChainName          string
		overlayChainName        string
		netoutLoggingChainName  string
		defaultIface            *net.Interface
	)

	var cniCommand = func(command, input string) *exec.Cmd {
		toReturn := exec.Command(paths.PathToPlugin)
		toReturn.Env = []string{
			"CNI_COMMAND=" + command,
			"CNI_CONTAINERID=" + containerID,
			"CNI_NETNS=/some/netns/path",
			"CNI_IFNAME=some-eth0",
			"CNI_PATH=" + paths.CNIPath,
			"CNI_ARGS=DEBUG=" + debugFileName,
			"PATH=/sbin",
		}
		toReturn.Stdin = strings.NewReader(input)

		return toReturn
	}

	AllIPTablesRules := func(tableName string) []string {
		iptablesSession, err := gexec.Start(exec.Command("iptables", "-w", "-S", "-t", tableName), GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(iptablesSession).Should(gexec.Exit(0))
		return strings.Split(string(iptablesSession.Out.Contents()), "\n")
	}

	GetInput := func(i InputStruct) string {
		inputBytes, err := json.Marshal(i)
		Expect(err).NotTo(HaveOccurred())
		return string(inputBytes)
	}

	BeforeEach(func() {
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		Expect(err).NotTo(HaveOccurred())

		var defaultIfaceIndex int
		for _, r := range routes {
			if r.Dst == nil {
				defaultIfaceIndex = r.LinkIndex
			}
		}

		defaultIface, err = net.InterfaceByIndex(defaultIfaceIndex)
		Expect(err).NotTo(HaveOccurred())

		healthCheckReturnStatus = http.StatusOK
		healthCheckServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(healthCheckReturnStatus)
		}))

		debugFile, err := ioutil.TempFile("", "cni_debug")
		Expect(err).NotTo(HaveOccurred())
		Expect(debugFile.Close()).To(Succeed())
		debugFileName = debugFile.Name()

		debug = &noop_debug.Debug{
			ReportResult:         `{ "ips": [{ "version": "4", "interface": -1, "address": "1.2.3.4/32" }]}`,
			ReportVersionSupport: []string{"0.3.0", "0.3.1"},
		}
		Expect(debug.WriteDebug(debugFileName)).To(Succeed())

		datastoreFile, err := ioutil.TempFile("", "datastore")
		Expect(err).NotTo(HaveOccurred())
		Expect(datastoreFile.Close()).To(Succeed())
		datastorePath = datastoreFile.Name()

		iptablesLockFile, err := ioutil.TempFile("", "iptables-lock")
		Expect(err).NotTo(HaveOccurred())
		Expect(iptablesLockFile.Close()).To(Succeed())
		iptablesLockFilePath = iptablesLockFile.Name()

		var code garden.ICMPCode = 0
		inputStruct = InputStruct{
			Name:       "cni-wrapper",
			CNIVersion: "0.3.0",
			Type:       "wrapper",
			Delegate: map[string]interface{}{
				"type": "noop",
				"some": "other data",
			},
			Metadata: map[string]interface{}{
				"key1": "value1",
				"key2": []string{"some", "data"},
			},
			WrapperConfig: lib.WrapperConfig{
				Datastore:        datastorePath,
				HealthCheckURL:   healthCheckServer.URL,
				IPTablesLockFile: iptablesLockFilePath,
				Delegate: map[string]interface{}{
					"type": "noop",
					"some": "other data",
				},
				InstanceAddress:    "10.244.2.3",
				IPTablesASGLogging: false,
				IngressTag:         "FFFF0000",
				VTEPName:           "some-device",
				RuntimeConfig: lib.RuntimeConfig{
					PortMappings: []garden.NetIn{
						{
							HostPort:      1000,
							ContainerPort: 1001,
						},
						{
							HostPort:      2000,
							ContainerPort: 2001,
						},
					},
					NetOutRules: []garden.NetOutRule{
						{
							Protocol: garden.ProtocolAll,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("3.3.3.3"),
									End:   net.ParseIP("4.4.4.4"),
								},
							},
						},
						{
							Protocol: garden.ProtocolTCP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("8.8.8.8"),
									End:   net.ParseIP("9.9.9.9"),
								},
							},
							Ports: []garden.PortRange{
								{
									Start: 53,
									End:   54,
								},
							},
						},
						{
							Protocol: garden.ProtocolUDP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("11.11.11.11"),
									End:   net.ParseIP("22.22.22.22"),
								},
							},
							Ports: []garden.PortRange{
								{
									Start: 53,
									End:   54,
								},
							},
						},
						{
							Protocol: garden.ProtocolICMP,
							Networks: []garden.IPRange{
								{
									Start: net.ParseIP("5.5.5.5"),
									End:   net.ParseIP("6.6.6.6"),
								},
							},
							ICMPs: &garden.ICMPControl{
								Type: 8,
								Code: &code,
							},
						},
					},
				},
			},
		}

		input = GetInput(inputStruct)

		containerID = "some-container-id-that-is-long"
		netinChainName = ("netin--" + containerID)[:28]
		netoutChainName = ("netout--" + containerID)[:28]
		inputChainName = ("input--" + containerID)[:28]
		overlayChainName = ("overlay--" + containerID)[:28]
		netoutLoggingChainName = fmt.Sprintf("%s--log", netoutChainName[:23])

		cmd = cniCommand("ADD", input)
	})

	AfterEach(func() {
		cmd := cniCommand("DEL", input)
		session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(session, "5s").Should(gexec.Exit(0))

		By("checking that ip masquerade rule is removed")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))

		By("checking that iptables netin rules are removed")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(`-N ` + netinChainName))
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(`-A PREROUTING -j ` + netinChainName))
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(`-N ` + netinChainName))
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(`-A PREROUTING -j ` + netinChainName))

		By("checking that all port forwarding rules were removed from the netin chain")
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(ContainSubstring(netinChainName)))
		Expect(AllIPTablesRules("nat")).ToNot(ContainElement(ContainSubstring(netinChainName)))

		By("checking that all mark rules were removed from the netin chain")
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(ContainSubstring(netinChainName)))
		Expect(AllIPTablesRules("mangle")).ToNot(ContainElement(ContainSubstring(netinChainName)))

		By("checking that there are no more netout rules for this container")
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(inputChainName)))
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(netoutChainName)))
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(netoutLoggingChainName)))

		By("checking that there are no more overlay rules for this container")
		Expect(AllIPTablesRules("filter")).ToNot(ContainElement(ContainSubstring(overlayChainName)))

		os.Remove(debugFileName)
		os.Remove(datastorePath)
		os.Remove(iptablesLockFilePath)

		healthCheckServer.Close()
	})

	Describe("state lifecycle", func() {
		It("stores and removes metadata with the lifetime of the container", func() {
			By("calling ADD")
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that metadata is stored")
			stateFileBytes, err := ioutil.ReadFile(datastorePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stateFileBytes)).To(ContainSubstring("1.2.3.4"))
			Expect(string(stateFileBytes)).To(ContainSubstring("value1"))

			By("calling DEL")
			cmd = cniCommand("DEL", input)
			session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that metadata is has been removed")
			stateFileBytes, err = ioutil.ReadFile(datastorePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(stateFileBytes)).NotTo(ContainSubstring("1.2.3.4"))
			Expect(string(stateFileBytes)).NotTo(ContainSubstring("value1"))
		})
	})

	Describe("iptables lifecycle", func() {
		It("adds and removes ip masquerade rules with the lifetime of the container", func() {
			By("calling ADD")
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that ip masquerade rule is created")
			Expect(AllIPTablesRules("nat")).To(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))

			By("calling DEL")
			cmd = cniCommand("DEL", input)
			session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("check that ip masquerade rule is removed")
			Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))
		})
	})

	Context("When call with command ADD", func() {
		It("passes the delegate result back to the caller", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(session.Out.Contents()).To(MatchJSON(`{ "ips": [{ "version": "4", "interface": -1, "address": "1.2.3.4/32" }], "dns":{} }`))
		})

		It("passes the correct stdin to the delegate plugin", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			debug, err := noop_debug.ReadDebug(debugFileName)
			Expect(err).NotTo(HaveOccurred())
			Expect(debug.Command).To(Equal("ADD"))

			Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
				"cniVersion": "0.3.0",
				"type": "noop",
				"some": "other data"
			}`))
		})

		It("ensures the container masquerade rule is created", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))
			Expect(session.Out.Contents()).To(MatchJSON(`{ "ips": [{ "version": "4", "interface": -1, "address": "1.2.3.4/32" }], "dns":{} }`))
			Expect(AllIPTablesRules("nat")).To(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))
		})

		It("writes default deny input chain rules to prevent connecting to things on the host", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("checking that the input chain jumps to the container's input chain")
			Expect(AllIPTablesRules("filter")).To(ContainElement("-A INPUT -s 1.2.3.4/32 -j " + inputChainName))

			By("checking that the default deny rules in the container's input chain are created")
			Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
				"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
				"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
			}))
		})

		It("writes default deny forward chain rules to prevent ingress, but allows specially marked packets", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			By("checking that the forward chain jumps to the container's overlay chain")
			Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -j " + overlayChainName))

			By("checking that the default rules in the container's overlay chain are created")
			Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
				"-A " + overlayChainName + " -s 1.2.3.4/32 -o some-device -m mark ! --mark 0x0 -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -m state --state RELATED,ESTABLISHED -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -m mark --mark 0xffff0000 -j ACCEPT",
				"-A " + overlayChainName + " -d 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable",
			}))
		})

		Context("when DNS servers are configured", func() {
			BeforeEach(func() {
				inputStruct.DNSServers = []string{"169.254.0.1", "8.8.4.4", "169.254.0.2"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("returns DNS info in the output", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("returning all DNS servers")
				Expect(session.Out.Contents()).To(MatchJSON(`{
				"ips": [{ "version": "4", "interface": -1, "address": "1.2.3.4/32" }],
				"dns": {"nameservers": ["169.254.0.1", "8.8.4.4", "169.254.0.2"]}
			}`))
			})

			It("writes input chain rules for local DNS servers", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the rules in the container's input chain are created for each local dns server")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					"-A " + inputChainName + " -m state --state RELATED,ESTABLISHED -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.1/32 -p tcp -m tcp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.1/32 -p udp -m udp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.2/32 -p tcp -m tcp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -d 169.254.0.2/32 -p udp -m udp --dport 53 -j ACCEPT",
					"-A " + inputChainName + " -j REJECT --reject-with icmp-port-unreachable",
				}))

				By("checking that no rules are created for public dns servers")
				Expect(AllIPTablesRules("filter")).NotTo(ContainElement(
					"-A " + inputChainName + " -d 8.8.4.4/32 -p tcp -m tcp --dport 53 -j ACCEPT",
				))
				Expect(AllIPTablesRules("filter")).NotTo(ContainElement(
					"-A " + inputChainName + " -d 8.8.4.4/32 -p udp -m udp --dport 53 -j ACCEPT",
				))

			})

		})

		Context("when some of the DNS servers are not valid IPs", func() {
			BeforeEach(func() {
				inputStruct.DNSServers = []string{"1.2.3.4", "banana"}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("returns an error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				var errData map[string]interface{}
				Expect(json.Unmarshal(session.Out.Contents(), &errData)).To(Succeed())
				Expect(errData["code"]).To(BeEquivalentTo(100))
				Expect(errData["msg"]).To(ContainSubstring(`invalid DNS server "banana", must be valid IP address`))
			})
		})

		Context("when no runtime config is passed in", func() {
			BeforeEach(func() {
				inputStruct.RuntimeConfig = lib.RuntimeConfig{}
				input = GetInput(inputStruct)

				cmd = cniCommand("ADD", input)
			})
			It("still writes the default netout rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the default forwarding rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the default input rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + inputChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + inputChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))
			})
		})

		Describe("PortMapping", func() {
			It("creates iptables portmapping rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that a netin chain was created for the container")
				Expect(AllIPTablesRules("nat")).To(ContainElement(`-N ` + netinChainName))
				Expect(AllIPTablesRules("nat")).To(ContainElement(`-A PREROUTING -j ` + netinChainName))

				By("checking that port forwarding rules were added to the netin chain")
				Expect(AllIPTablesRules("nat")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -p tcp -m tcp --dport 1000 -j DNAT --to-destination 1.2.3.4:1001"))
				Expect(AllIPTablesRules("nat")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -p tcp -m tcp --dport 2000 -j DNAT --to-destination 1.2.3.4:2001"))
			})

			It("creates mark rules for each port mapping rule", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that a netin chain was created for the container")
				Expect(AllIPTablesRules("mangle")).To(ContainElement(`-N ` + netinChainName))
				Expect(AllIPTablesRules("mangle")).To(ContainElement(`-A PREROUTING -j ` + netinChainName))

				By("checking that mark rules were added to the netin chain")
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + defaultIface.Name + " -p tcp -m tcp --dport 1000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
				Expect(AllIPTablesRules("mangle")).To(ContainElement("-A " + netinChainName + " -d 10.244.2.3/32 -i " + defaultIface.Name + " -p tcp -m tcp --dport 2000 -j MARK --set-xmark 0xffff0000/0xffffffff"))
			})

			Context("when a port mapping with hostport 0 is given", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.PortMappings = []garden.NetIn{
						{
							HostPort:      0,
							ContainerPort: 1001,
						},
					}

					input = GetInput(inputStruct)
				})
				It("refuses to allocate", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(1))
				})
			})

			Context("when adding netin rule fails", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.InstanceAddress = "asdf"
					input = GetInput(inputStruct)
				})
				It("exit status 1", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(1))
					Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 100, "msg": "adding netin rule: invalid ip: asdf" }`))
				})
			})
		})

		Describe("NetOutRules", func() {
			It("creates iptables netout rules", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				By("checking that the jump rules are created for that container's netout chain")
				Expect(AllIPTablesRules("filter")).To(ContainElement("-A FORWARD -s 1.2.3.4/32 -o " + defaultIface.Name + " -j " + netoutChainName))

				By("checking that the default forwarding rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the default input rules are created for that container")
				Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
					`-A ` + inputChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
					`-A ` + inputChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
				}))

				By("checking that the rules are written")
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -m iprange --dst-range 3.3.3.3-4.4.4.4 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p udp -m iprange --dst-range 11.11.11.11-22.22.22.22 -m udp --dport 53:54 -j ACCEPT`))
				Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p icmp -m iprange --dst-range 5.5.5.5-6.6.6.6 -m icmp --icmp-type 8/0 -j ACCEPT`))

			})

			Context("when iptables_c2c_logging is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.IPTablesC2CLogging = true
					input = GetInput(inputStruct)
				})

				It("writes iptables overlay logging rules", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the default deny rules in the container's overlay chain are created")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						"-A " + overlayChainName + " -s 1.2.3.4/32 -o some-device -m mark ! --mark 0x0 -j ACCEPT",
						"-A " + overlayChainName + " -d 1.2.3.4/32 -m state --state RELATED,ESTABLISHED -j ACCEPT",
						"-A " + overlayChainName + " -d 1.2.3.4/32 -m mark --mark 0xffff0000 -j ACCEPT",
						"-A " + overlayChainName + ` -d 1.2.3.4/32 -m limit --limit 2/min -j LOG --log-prefix "DENY_C2C_` + containerID[:19] + ` "`,
						"-A " + overlayChainName + " -d 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable",
					}))
				})
			})

			Context("when iptables_asg_logging is enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[0].Log = false
					inputStruct.WrapperConfig.IPTablesASGLogging = true
					input = GetInput(inputStruct)
				})

				It("writes iptables asg logging rules", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -g ` + netoutLoggingChainName))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutLoggingChainName + ` -p tcp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`))
				})

				It("always writes a rate limited default deny log rule", func() {
					expectedDenyLogRule := `-A netout--some-container-id-th -m limit --limit 2/min -j LOG --log-prefix "DENY_` + containerID[:23] + ` "`

					By("by starting the CNI plugin")
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that a default deny log rule was written")
					Expect(AllIPTablesRules("filter")).To(gomegamatchers.ContainSequence([]string{
						`-A ` + netoutChainName + ` -m state --state RELATED,ESTABLISHED -j ACCEPT`,
						expectedDenyLogRule,
						`-A ` + netoutChainName + ` -j REJECT --reject-with icmp-port-unreachable`,
					}))
				})
			})

			Context("when a rule has logging enabled", func() {
				BeforeEach(func() {
					inputStruct.WrapperConfig.RuntimeConfig.NetOutRules[1].Log = true
					inputStruct.WrapperConfig.IPTablesASGLogging = false
					input = GetInput(inputStruct)
				})
				It("writes iptables asg logging rules for that rule", func() {
					cmd = cniCommand("ADD", input)
					session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					By("checking that the filter rule was installed and that logging can be enabled")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutChainName + ` -p tcp -m iprange --dst-range 8.8.8.8-9.9.9.9 -m tcp --dport 53:54 -g ` + netoutLoggingChainName))

					By("checking that it writes the logging rules")
					Expect(AllIPTablesRules("filter")).To(ContainElement(`-A ` + netoutLoggingChainName + ` -p tcp -m conntrack --ctstate INVALID,NEW,UNTRACKED -j LOG --log-prefix "OK_` + containerID[:25] + ` "`))
				})
			})
		})

		Context("When the health check call returns an error", func() {
			BeforeEach(func() {
				healthCheckServer.Close()
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))
				var errData map[string]interface{}
				Expect(json.Unmarshal(session.Out.Contents(), &errData)).To(Succeed())
				Expect(errData["code"]).To(BeEquivalentTo(100))
				Expect(errData["msg"]).To(ContainSubstring("could not call health check: Get http"))
			})
		})

		Context("When the health check returns a non-200 status code", func() {
			BeforeEach(func() {
				healthCheckReturnStatus = 503
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))
				var errData map[string]interface{}
				Expect(json.Unmarshal(session.Out.Contents(), &errData)).To(Succeed())
				Expect(errData["code"]).To(BeEquivalentTo(100))
				Expect(errData["msg"]).To(ContainSubstring("health check failed with 503"))
			})
		})

		Context("When the delegate plugin returns an error", func() {
			BeforeEach(func() {
				debug.ReportError = "banana"
				Expect(debug.WriteDebug(debugFileName)).To(Succeed())
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 100, "msg": "delegate call: banana" }`))
			})
		})

		Context("when the container id is not specified", func() {
			BeforeEach(func() {
				cmd.Env[1] = "CNI_CONTAINERID="
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 100, "msg": "store add: invalid handle" }`))
			})

			It("does not leave any iptables rules behind", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))
			})
		})

		Context("when the datastore add fails", func() {
			BeforeEach(func() {
				err := ioutil.WriteFile(datastorePath, []byte("banana"), os.ModePerm)
				Expect(err).NotTo(HaveOccurred())
			})

			It("wraps and returns the error", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(session.Out.Contents()).To(MatchJSON(`{ "code": 100, "msg": "store add: decoding file: invalid character 'b' looking for beginning of value" }`))
			})

			It("does not leave any iptables rules behind", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(1))

				Expect(AllIPTablesRules("nat")).NotTo(ContainElement("-A POSTROUTING -s 1.2.3.4/32 ! -o some-device -j MASQUERADE"))
			})
		})
	})

	Context("When call with command DEL", func() {
		BeforeEach(func() {
			cmd.Env[0] = "CNI_COMMAND=DEL"
		})

		It("passes the correct stdin to the delegate plugin", func() {
			session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			debug, err := noop_debug.ReadDebug(debugFileName)
			Expect(err).NotTo(HaveOccurred())
			Expect(debug.Command).To(Equal("DEL"))

			Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
				"cniVersion": "0.3.0",
				"type": "noop",
				"some": "other data"
			}`))
		})

		Context("When the delegate plugin return an error", func() {
			BeforeEach(func() {
				debug.ReportError = "banana"
				Expect(debug.WriteDebug(debugFileName)).To(Succeed())
			})

			It("logs the wrapped error to stderr and return the success status code (for idempotency)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(session.Err.Contents()).To(ContainSubstring("delegate delete: banana"))
			})
		})

		Context("when the datastore delete fails", func() {
			BeforeEach(func() {
				cmd.Env[1] = "CNI_CONTAINERID="
			})

			It("wraps and logs the error, and returns the success status code (for idempotency)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				Expect(session.Err.Contents()).To(ContainSubstring("store delete: invalid handle"))
			})

			It("still calls plugin delete (so that DEL is idempotent)", func() {
				session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				debug, err := noop_debug.ReadDebug(debugFileName)
				Expect(err).NotTo(HaveOccurred())
				Expect(debug.Command).To(Equal("DEL"))

				Expect(debug.CmdArgs.StdinData).To(MatchJSON(`{
					"cniVersion": "0.3.0",
					"type": "noop",
					"some": "other data"
				}`))
			})
		})

	})
})
