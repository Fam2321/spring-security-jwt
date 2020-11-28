package com.security.jwt.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class Controller {
    @GetMapping(value = ["/"])
    fun hello(): String {
        return "hello"
    }
}