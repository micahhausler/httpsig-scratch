/*
The attributes package holds the identity types that key directories resolve
and verified request handlers consume.
*/
package attributes

// User is a holder for a username
type User struct {
	Username string `json:"username"`
}
