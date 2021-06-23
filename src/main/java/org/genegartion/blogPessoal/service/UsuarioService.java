package org.genegartion.blogPessoal.service;

import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;
import java.util.Optional;
import org.genegartion.blogPessoal.model.UserLogin;
import org.genegartion.blogPessoal.model.Usuario;
import org.genegartion.blogPessoal.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {
	@Autowired
	private UsuarioRepository repository;

	public Optional<Usuario> cadastrarUsuario(Usuario usuarioNovo) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String senhaCriptografada = encoder.encode(usuarioNovo.getSenha());
		usuarioNovo.setSenha(senhaCriptografada);
		return Optional.ofNullable(repository.save(usuarioNovo));
	}

	public Optional<UserLogin> logar(Optional<UserLogin> loginUser) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		Optional<Usuario> usuarioPresente = repository.findByUsuario(loginUser.get().getUsuario());
		if (usuarioPresente.isPresent()) {
			if (encoder.matches(loginUser.get().getSenha(), usuarioPresente.get().getSenha())) {
				String auth = loginUser.get().getUsuario() + ":" + loginUser.get().getSenha();
				byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
				String token = "Basic " + new String(encodedAuth);
				loginUser.get().setToken(token);
				loginUser.get().setId(usuarioPresente.get().getId());
				loginUser.get().setNome(usuarioPresente.get().getNome());
				loginUser.get().setSenha(usuarioPresente.get().getSenha());
				loginUser.get().setFoto(usuarioPresente.get().getFoto());
				loginUser.get().setTipo(usuarioPresente.get().getTipo());
			
				
				return loginUser;
			}
		}
		return null;
	}

}
