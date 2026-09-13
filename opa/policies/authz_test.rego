package authz

test_admin_can_delete if {
    allow with input as {
        "user": {
            "role": "admin"
        },
        "method": "DELETE",
        "resource": "widget"
    }
}

test_user_can_get if {
    allow with input as {
        "user": {
            "role": "user"
        },
        "method": "GET",
        "resource": "widget"
    }
}

test_user_can_post if {
    allow with input as {
        "user": {
            "role": "user"
        },
        "method": "POST",
        "resource": "widget"
    }
}

test_user_cannot_delete if {
    not allow with input as {
        "user": {
            "role": "user"
        },
        "method": "DELETE",
        "resource": "widget"
    }
}

test_guest_can_get if {
    allow with input as {
        "user": {
            "role": "guest"
        },
        "method": "GET",
        "resource": "widget"
    }
}

test_guest_cannot_post if {
    not allow with input as {
        "user": {
            "role": "guest"
        },
        "method": "POST",
        "resource": "widget"
    }
}