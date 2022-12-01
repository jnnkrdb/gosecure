package jcloak

import "time"

// SetLegacyWildFlySupport maintain legacy WildFly support.
func SetLegacyWildFlySupport() func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.authAdminRealms = makeURL("auth", "admin", "realms")
		g.Config.authRealms = makeURL("auth", "realms")
	}
}

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.authRealms = url
	}
}

// SetAuthAdminRealms sets the auth admin realm
func SetAuthAdminRealms(url string) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.authAdminRealms = url
	}
}

// SetTokenEndpoint sets the token endpoint
func SetTokenEndpoint(url string) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.tokenEndpoint = url
	}
}

// SetLogoutEndpoint sets the logout
func SetLogoutEndpoint(url string) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.logoutEndpoint = url
	}
}

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.openIDConnect = url
	}
}

// SetCertCacheInvalidationTime sets the logout
func SetCertCacheInvalidationTime(duration time.Duration) func(g *JCloak) {
	return func(g *JCloak) {
		g.Config.CertsInvalidateTime = duration
	}
}
