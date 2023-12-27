package io.security.corespringsecurity.controller.user;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

	@GetMapping(value = "/messages")
	public String mypage() throws Exception {

		return "user/messages";
	}

	@ResponseBody
	@GetMapping("/api/messages")
	public String messages() {
		return "Message OK";
	}
}
