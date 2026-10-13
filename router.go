package routing_table

type router struct {
	v4ribs []*IPv4Rib
	v6ribs []*IPv6Rib
}

// Deprecated: router has no lookup functionality and is unused; GetNewRouter and
// its methods will be removed in a future release. Manage IPv4Rib/IPv6Rib directly.
func GetNewRouter() router {
	return router{}
}

// Deprecated: see GetNewRouter.
func (r *router) Size() int {
	return len(r.v4ribs) + len(r.v6ribs)
}

// Deprecated: see GetNewRouter.
func (r *router) AddIPv4Rib(rib *IPv4Rib) {
	r.v4ribs = append(r.v4ribs, rib)
}

// Deprecated: see GetNewRouter.
func (r *router) AddIPv6Rib(rib *IPv6Rib) {
	r.v6ribs = append(r.v6ribs, rib)
}
