package option

type _Host struct {
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`
}

type Host _Host
