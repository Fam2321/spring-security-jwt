package com.security.jwt.controller

import com.security.jwt.config.JwtTokenUtil
import com.security.jwt.model.JwtRequest
import com.security.jwt.model.JwtResponse
import com.security.jwt.service.JwtUserDetailsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
@CrossOrigin
class JwtAuthenticationController {
    @Autowired
    private val authenticationManager: AuthenticationManager? = null

    @Autowired
    private val jwtTokenUtil: JwtTokenUtil? = null

    @Autowired
    private val userDetailsService: JwtUserDetailsService? = null

    @PostMapping(value = ["/authenticate"])
    @Throws(Exception::class)
    fun createAuthenticationToken(@RequestBody authenticationRequest: JwtRequest): ResponseEntity<*>? {
        authenticate(authenticationRequest.username, authenticationRequest.password)
        val userDetails = userDetailsService?.loadUserByUsername(authenticationRequest.username)
        val token: String = jwtTokenUtil!!.generateToken(userDetails)
        return ResponseEntity.ok<Any>(JwtResponse(jwttoken = token))
    }

    @Throws(java.lang.Exception::class)
    private fun authenticate(username: String, password: String) {
        try {
            authenticationManager!!.authenticate(UsernamePasswordAuthenticationToken(username, password))
        } catch (e: DisabledException) {
            throw java.lang.Exception("USER_DISABLED", e)
        } catch (e: BadCredentialsException) {
            throw java.lang.Exception("INVALID_CREDENTIALS", e)
        }
    }
}