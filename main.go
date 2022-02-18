package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Telmate/proxmox-api-go/proxmox"
	"github.com/go-kit/log"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/documentation/examples/custom-sd/adapter"
	"github.com/sirupsen/logrus"
)

type discovery struct {
	client  *proxmox.Client
	port    int
	refresh int
	lasts   map[string]struct{}
	logger  log.Logger
}

type virtualmachine struct {
	CPU       float64
	Disk      int
	Diskread  int64
	Diskwrite int64
	ID        string
	Maxcpu    int
	Maxdisk   int64
	Maxmem    int64
	Mem       int64
	Name      string
	Netin     int64
	Netout    int64
	Node      string
	Status    string
	Template  int
	Type      string
	Uptime    int
	Vmid      int
}

const (
	proxmoxLabelPrefix     = model.MetaLabelPrefix + "proxmox_"
	proxmoxLabelPublicIPv4 = proxmoxLabelPrefix + "pve_ip"
	proxmoxLabelHostname   = proxmoxLabelPrefix + "pve_name"
	proxmoxLabelVmID       = proxmoxLabelPrefix + "pve_vm_id"
	proxmoxLabelNode       = proxmoxLabelPrefix + "pve_node"
)

var (
	outputf         string
	pveHost         string
	pveUser         string
	pvePassword     string
	pveOTP          string
	pveAPIToken     string
	pveExcludeVMID  string
	cidr            string
	pveInsecure     bool
	refreshInterval int
	port            int
)

func init() {
	flag.StringVar(&outputf, "output", "proxmox.json", "The output filename for file_sd compatible file.")
	flag.StringVar(&pveHost, "host", "http://127.0.0.1", "IP address from PVE host system")
	flag.StringVar(&pveUser, "user", "", "Username for the PVE host system")
	flag.StringVar(&pvePassword, "password", "", "Password for the PVE host system")
	flag.StringVar(&pveOTP, "otp", "", "OTP for the PVE host system")
	flag.StringVar(&pveAPIToken, "token", "", "API Token for the PVE host system")
	flag.StringVar(&pveExcludeVMID, "exclude-vm", "", "Comma separated list of VM IDs to be excluded from SD")
	flag.StringVar(&cidr, "cidr", "", "Only IP addresses in this CIDR are included")
	flag.IntVar(&refreshInterval, "refresh", 30, "Interval of the update in seconds")
	flag.IntVar(&port, "target-port", 9100, "Port for the target")
	flag.BoolVar(&pveInsecure, "insecure", true, "Connect to PVE host system via insecure connection")
}

func main() {
	flag.Parse()
	logrus.Info("Starting Proxmox SD...")

	if len(pveUser) == 0 {
		logrus.Fatal("Missing PVE user")
	}

	if len(pveHost) == 0 {
		logrus.Fatal("Missing PVE host")
	}

	tlsconf := &tls.Config{InsecureSkipVerify: true}
	if !pveInsecure {
		tlsconf = nil
	}

	c, err := proxmox.NewClient(pveHost, nil, tlsconf, "", 300)
	if err != nil {
		logrus.WithError(err).Fatal("Could not create PVE client")
	}
	if userRequiresAPIToken(pveUser) {
		logrus.Info("Using API Token")
		if len(pveAPIToken) == 0 {
			logrus.Fatal("Missing PVE token")
		}
		c.SetAPIToken(pveUser, pveAPIToken)
		_, err = c.GetVersion()
		if err != nil {
			logrus.WithError(err).Fatal("Could not login to PVE host system")
		}
	} else {
		logrus.Info("Using Username/Password Login")
		if len(pvePassword) == 0 {
			logrus.Fatal("Missing PVE password")
		}
		err = c.Login(pveUser, pvePassword, pveOTP)
		if err != nil {
			logrus.WithError(err).Fatal("Could not login to PVE host system")
		}
	}
	logger := log.NewSyncLogger(log.NewLogfmtLogger(logrus.New().Writer()))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	disc := &discovery{
		client:  c,
		refresh: refreshInterval,
		logger:  logger,
		port:    port,
		lasts:   make(map[string]struct{}),
	}
	ctx := context.Background()
	sdAdapter := adapter.NewAdapter(ctx, outputf, "proxmoxSD", disc, logger)
	sdAdapter.Run()

	<-ctx.Done()
}

func (c *discovery) getTargets() ([]*targetgroup.Group, error) {
	vmList, err := c.client.GetVmList()
	if err != nil {
		logrus.WithError(err).Fatal("Could not retrieve node list")
		return nil, err
	}

	current := make(map[string]struct{})

	retArr := filter(vmList["data"].([]interface{}))
	var tgs []*targetgroup.Group

	for _, vm := range retArr {
		vmr := proxmox.NewVmRef(vm.Vmid)

		netC, err := c.client.GetVmAgentNetworkInterfaces(vmr)
		if err != nil && !strings.Contains(err.Error(), "No QEMU guest agent configured") {
			logrus.WithError(err).Fatal("Could not retrieve VmAgentNetworkInterfaces")
			return nil, err
		}
		for _, nc := range netC {
			for _, ip := range nc.IPAddresses {
				if ip.IsLoopback() || ip.To4() == nil {
					continue
				}
				if len(cidr) > 0 {
					_, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						logrus.WithError(err).Fatal("Could not parse CIDR")
						return nil, err
					}
					if !ipnet.Contains(ip) {
						continue
					}
				}
				tg := c.createTarget(ip.String(), vm)
				tgs = append(tgs, tg)
				current[tg.Source] = struct{}{}
			}
		}

	}

	for k := range c.lasts {
		if _, ok := current[k]; !ok {
			tgs = append(tgs, &targetgroup.Group{Source: k})
		}
	}

	return tgs, nil
}

func (c *discovery) createTarget(ip string, vm virtualmachine) *targetgroup.Group {

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", c.port))

	return &targetgroup.Group{
		Source: fmt.Sprintf("scaleway/%s_%s", strconv.Itoa(vm.Vmid), vm.Node),
		Targets: []model.LabelSet{
			model.LabelSet{
				model.AddressLabel: model.LabelValue(addr),
			},
		},
		Labels: model.LabelSet{
			model.AddressLabel:                      model.LabelValue(ip),
			model.LabelName(proxmoxLabelHostname):   model.LabelValue(vm.Name),
			model.LabelName(proxmoxLabelNode):       model.LabelValue(vm.Node),
			model.LabelName(proxmoxLabelPublicIPv4): model.LabelValue(ip),
			model.LabelName(proxmoxLabelVmID):       model.LabelValue(strconv.Itoa(vm.Vmid)),
		},
	}
}

func userRequiresAPIToken(userID string) bool {
	rxUserRequiresToken := regexp.MustCompile("[a-z0-9]+@[a-z0-9]+![a-z0-9]+")
	return rxUserRequiresToken.MatchString(userID)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func filter(vmList []interface{}) (retArry []virtualmachine) {
	var tmpArray []virtualmachine
	excludedVMS := strings.Split(pveExcludeVMID, ",")
	for _, v := range vmList {
		var vm virtualmachine
		mapstructure.Decode(v, &vm)
		if vm.Template == 1 || vm.Status == "stopped" || stringInSlice(strconv.Itoa(vm.Vmid), excludedVMS) {
			// Skip templates & stopped vm & excluded vms
			continue
		}
		tmpArray = append(tmpArray, vm)
	}
	return tmpArray
}

func (d *discovery) Run(ctx context.Context, ch chan<- []*targetgroup.Group) {
	for c := time.Tick(time.Duration(d.refresh) * time.Second); ; {
		tgs, err := d.getTargets()
		if err == nil {
			ch <- tgs
		}

		// Wait for ticker or exit when ctx is closed.
		select {
		case <-c:
			continue
		case <-ctx.Done():
			return
		}
	}
}
