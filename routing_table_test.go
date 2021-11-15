package routing_table_test

import (
	"testing"

	rib "github.com/mellowdrifter/routing_table"
)

func TestNewRib(t *testing.T) {
	router := rib.GetNewRib()
	t.Errorf("%+v\n", router)
}
