package authz

default allow := false

allow if {
    input.user.role == "admin"
}

allow if {
    input.user.role == "user"
    input.method == "GET"
}

allow if {
    input.user.role == "user"
    input.method == "POST"
}

allow if {
    input.user.role == "guest"
    input.method == "GET"
}