package authitem

import "strings"

// Store is a helper map that authenticates legacy users.
type Store map[string]*AuthItem

// NewStoreFromCLI returns a new Store map from a slice of user:pass strings.
//
//nolint:gomnd // tokenising colon separated key:value.
func NewStoreFromCLI(users []string) Store {
	store := Store{}

	for _, user := range users {
		s := strings.SplitN(user, ":", 2)

		if len(s) == 2 {
			store.Add(s[0], s[1])
		}
	}

	return store
}

// Authenticate looks for and validates a username and password combination against
// the map.
func (s Store) Authenticate(username, password string) bool {
	if v, ok := s[strings.ToLower(username)]; ok {
		return v.Authenticate([]byte(password))
	}

	return false
}

// Add adds a username and password combination to the map.
func (s Store) Add(username, password string) {
	s[username] = NewAuthItem(username, password)
}
