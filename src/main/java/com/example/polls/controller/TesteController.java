package com.example.polls.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.polls.payload.ApiResponse;

@RestController
@RequestMapping("/api/polls/teste")
public class TesteController {
	
	@GetMapping("/usuario")
	@PreAuthorize("hasRole('USER')")
	public ApiResponse testeUsuario() {
		return new ApiResponse(true, "Teste de Sucesso!");
	}
	
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public ApiResponse testeAdmin() {
		return new ApiResponse(true, "Teste de Sucesso!");
	}

}
