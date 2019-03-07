package builtin

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/threefoldtech/0-core/base/nft"
	"github.com/threefoldtech/0-core/base/pm"
)

type nftMgr struct{}

func init() {
	b := &nftMgr{}

	pm.RegisterBuiltIn("nft.open_port", b.openPort)
	pm.RegisterBuiltIn("nft.drop_port", b.dropPort)
	pm.RegisterBuiltIn("nft.list", b.listPorts)
	pm.RegisterBuiltIn("nft.rule_exists", b.ruleExists)

}

type Port struct {
	Port      uint16 `json:"port"`
	Interface string `json:"interface,omitempty"`
	Subnet    string `json:"subnet,omitempty"`
}

func getArgs(cmd *pm.Command) (args Port, err error) {
	err = json.Unmarshal(*cmd.Arguments, &args)
	return
}

func (p *Port) getRule() string {
	body := ""
	if p.Interface != "" {
		body += fmt.Sprintf(`iifname "%s" `, p.Interface)
	}

	if p.Subnet != "" {
		subnet := p.Subnet
		_, net, err := net.ParseCIDR(p.Subnet)
		if err == nil {
			subnet = net.String()
		}

		body += fmt.Sprintf(`ip saddr %s `, subnet)
	}

	body += fmt.Sprintf(`tcp dport %d accept`, p.Port)

	return body
}

func (b *nftMgr) openPort(cmd *pm.Command) (interface{}, error) {
	args, err := getArgs(cmd)
	if err != nil {
		return nil, err
	}

	matches, err := nft.Find(nft.And{
		&nft.TableFilter{Table: "filter"},
		&nft.ChainFilter{Chain: "input"},
		&nft.IntMatchFilter{Name: "tcp", Field: "dport", Value: uint64(args.Port)},
	})

	if err != nil {
		return nil, err
	}

	if len(matches) != 0 {
		return nil, fmt.Errorf("rule already exists for port: %d", args.Port)
	}

	n := nft.Nft{
		"filter": nft.Table{
			Family: nft.FamilyINET,
			Chains: nft.Chains{
				"input": nft.Chain{
					Rules: []nft.Rule{
						{Body: args.getRule()},
					},
				},
			},
		},
	}

	if err := nft.Apply(n); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *nftMgr) dropPort(cmd *pm.Command) (interface{}, error) {
	args, err := getArgs(cmd)
	if err != nil {
		return nil, err
	}

	matches, err := nft.Find(nft.And{
		&nft.TableFilter{Table: "filter"},
		&nft.ChainFilter{Chain: "input"},
		&nft.IntMatchFilter{Name: "tcp", Field: "dport", Value: uint64(args.Port)},
	})

	if err != nil {
		return nil, err
	}

	for _, rule := range matches {
		if err := nft.Drop(nft.FamilyINET, "filter", "input", rule.Handle); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (b *nftMgr) listPorts(cmd *pm.Command) (interface{}, error) {
	matches, err := nft.Find(nft.And{
		&nft.TableFilter{Table: "filter"},
		&nft.ChainFilter{Chain: "input"},
	})

	if err != nil {
		return nil, err
	}

	var rules []string
	for _, rule := range matches {
		rules = append(rules, rule.Body)
	}

	return rules, nil
}

func (b *nftMgr) ruleExists(cmd *pm.Command) (interface{}, error) {
	args, err := getArgs(cmd)
	if err != nil {
		return nil, err
	}

	matches, err := nft.Find(nft.And{
		&nft.TableFilter{Table: "filter"},
		&nft.ChainFilter{Chain: "input"},
		&nft.IntMatchFilter{Name: "tcp", Field: "dport", Value: uint64(args.Port)},
	})

	if err != nil {
		return nil, err
	}

	return len(matches) > 0, nil
}
