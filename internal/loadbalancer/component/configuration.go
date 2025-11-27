package component

import (
	"net/url"
)

type Configuration struct {
	Hosts []Host
}

type Host struct {
	Host    url.URL
	Targets []url.URL
}
