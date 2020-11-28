package com.security.jwt.model

import java.io.Serializable

data class JwtRequest(
    val username: String,
    val password: String
): Serializable