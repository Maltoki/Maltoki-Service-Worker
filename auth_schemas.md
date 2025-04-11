
# Register

```jsonc
{
    "service":"register",
    "data":{
        "email":"...",
        "first_name":"...",
        "last_name":"...",
        "password":"...",
        "re-password":"...",
        "DOB":"..."
    }
}
```

# login

```jsonc
{
    "service":"login",
    "data":{
        "email":"...",
        "password":"..."
    }
}
```

# refresh_login

```jsonc
{
    "service":"refresh_login",
    "data":{
        "refresh_token":"..."
    }
}
```

# verify_account

```jsonc
{
    "service":"verify_account",
    "data":{
        "access_token":"..."
    }
}
```

# verify_API_key

```jsonc
{
    "service":"verify_API_key",
    "data":{
        "api_key":"..."
    }
}
```

# generate_API_key

```jsonc
{
    "service":"generate_API_key",
    "data":{
        "access_token":"..." // JWT token
    }
}
```