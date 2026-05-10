package routing_table

type router struct {
	v4ribs []*IPv4Rib
	v6ribs []*IPv6Rib
}

func GetNewRouter() router {
	return router{}
}

func (r *router) Size() int {
	return len(r.v4ribs) + len(r.v6ribs)
}

func (r *router) AddIPv4Rib(rib *IPv4Rib) {
	r.v4ribs = append(r.v4ribs, rib)
}

func (r *router) AddIPv6Rib(rib *IPv6Rib) {
	r.v6ribs = append(r.v6ribs, rib)
}
